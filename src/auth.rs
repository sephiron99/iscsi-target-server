//! RFC 7143 12.1.3절의 단방향 CHAP 인증.

use std::fmt;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use md5::{Digest, Md5};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::login::TextParameters;

pub const CHAP_MD5_ALGORITHM: u8 = 5;
pub const DEFAULT_CHAP_CHALLENGE_LENGTH: usize = 32;
pub const MAX_CHAP_BINARY_LENGTH: usize = 1024;

pub struct ChapCredentials {
    username: String,
    secret: Zeroizing<Vec<u8>>,
}

impl ChapCredentials {
    pub fn new(username: String, secret: Vec<u8>) -> Result<Self, ChapError> {
        if username.is_empty() || username.as_bytes().contains(&0) {
            return Err(ChapError::InvalidUsername);
        }
        if secret.is_empty() || secret.len() > MAX_CHAP_BINARY_LENGTH {
            return Err(ChapError::InvalidSecretLength {
                len: secret.len(),
                max: MAX_CHAP_BINARY_LENGTH,
            });
        }
        Ok(Self {
            username,
            secret: Zeroizing::new(secret),
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

impl fmt::Debug for ChapCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChapCredentials")
            .field("username", &self.username)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone)]
enum ChapState {
    AwaitingAlgorithm,
    ChallengeIssued { identifier: u8, challenge: Vec<u8> },
    Authenticated,
}

#[derive(Debug, Clone)]
pub struct ChapExchange {
    credentials: Arc<ChapCredentials>,
    state: ChapState,
}

impl ChapExchange {
    pub fn new(credentials: Arc<ChapCredentials>) -> Self {
        Self {
            credentials,
            state: ChapState::AwaitingAlgorithm,
        }
    }

    pub fn challenge(&mut self, proposal: &str) -> Result<TextParameters, ChapError> {
        if !matches!(self.state, ChapState::AwaitingAlgorithm) {
            return Err(ChapError::UnexpectedMessage);
        }
        if !proposal
            .split(',')
            .filter_map(|value| value.parse::<u8>().ok())
            .any(|algorithm| algorithm == CHAP_MD5_ALGORITHM)
        {
            return Err(ChapError::UnsupportedAlgorithm);
        }

        let mut identifier = [0u8; 1];
        let mut challenge = vec![0u8; DEFAULT_CHAP_CHALLENGE_LENGTH];
        getrandom::fill(&mut identifier).map_err(|_| ChapError::RandomSource)?;
        getrandom::fill(&mut challenge).map_err(|_| ChapError::RandomSource)?;

        let mut response = TextParameters::new();
        response.push("CHAP_A", &CHAP_MD5_ALGORITHM.to_string());
        response.push("CHAP_I", &identifier[0].to_string());
        response.push("CHAP_C", &encode_hex(&challenge));
        self.state = ChapState::ChallengeIssued {
            identifier: identifier[0],
            challenge,
        };
        Ok(response)
    }

    pub fn verify(&mut self, username: &str, encoded_response: &str) -> Result<(), ChapError> {
        let ChapState::ChallengeIssued {
            identifier,
            challenge,
        } = &self.state
        else {
            return Err(ChapError::UnexpectedMessage);
        };
        let received = decode_binary(encoded_response)?;
        let mut hasher = Md5::new();
        hasher.update([*identifier]);
        hasher.update(self.credentials.secret.as_slice());
        hasher.update(challenge);
        let expected = hasher.finalize();

        let name_matches = username
            .as_bytes()
            .ct_eq(self.credentials.username.as_bytes());
        let response_matches = received.as_slice().ct_eq(expected.as_slice());
        if bool::from(name_matches & response_matches) {
            self.state = ChapState::Authenticated;
            Ok(())
        } else {
            Err(ChapError::AuthenticationFailed)
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, ChapState::Authenticated)
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ChapError {
    #[error("CHAP username is empty or contains NUL")]
    InvalidUsername,
    #[error("CHAP secret length {len} is outside 1..={max}")]
    InvalidSecretLength { len: usize, max: usize },
    #[error("CHAP message is not valid in the current authentication state")]
    UnexpectedMessage,
    #[error("initiator did not offer CHAP algorithm 5")]
    UnsupportedAlgorithm,
    #[error("CHAP binary value is malformed or exceeds the limit")]
    InvalidBinaryValue,
    #[error("CHAP authentication failed")]
    AuthenticationFailed,
    #[error("operating system random source failed")]
    RandomSource,
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn decode_binary(value: &str) -> Result<Zeroizing<Vec<u8>>, ChapError> {
    let decoded = if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > MAX_CHAP_BINARY_LENGTH * 2 {
            return Err(ChapError::InvalidBinaryValue);
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            let high = hex_digit(pair[0]).ok_or(ChapError::InvalidBinaryValue)?;
            let low = hex_digit(pair[1]).ok_or(ChapError::InvalidBinaryValue)?;
            bytes.push((high << 4) | low);
        }
        bytes
    } else if let Some(base64) = value.strip_prefix("0b") {
        if base64.len() > 4 * MAX_CHAP_BINARY_LENGTH.div_ceil(3) {
            return Err(ChapError::InvalidBinaryValue);
        }
        STANDARD
            .decode(base64)
            .map_err(|_| ChapError::InvalidBinaryValue)?
    } else {
        return Err(ChapError::InvalidBinaryValue);
    };
    if decoded.len() > MAX_CHAP_BINARY_LENGTH {
        return Err(ChapError::InvalidBinaryValue);
    }
    Ok(Zeroizing::new(decoded))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_known_chap_md5_vector_without_exposing_secret() {
        let credentials =
            Arc::new(ChapCredentials::new("initiator".to_owned(), b"secret".to_vec()).unwrap());
        assert_eq!(
            format!("{credentials:?}"),
            "ChapCredentials { username: \"initiator\", secret: \"[REDACTED]\" }"
        );
        let mut exchange = ChapExchange {
            credentials,
            state: ChapState::ChallengeIssued {
                identifier: 7,
                challenge: b"challenge".to_vec(),
            },
        };
        // MD5(0x07 || "secret" || "challenge"), Python hashlib로 독립 확인.
        exchange
            .verify("initiator", "0x35524f3f6d24a5b27d3a2ff77c7c5060")
            .unwrap();
        assert!(exchange.is_authenticated());
    }

    #[test]
    fn rejects_wrong_name_response_and_oversized_binary_before_allocation() {
        let credentials =
            Arc::new(ChapCredentials::new("initiator".to_owned(), b"secret".to_vec()).unwrap());
        let state = ChapState::ChallengeIssued {
            identifier: 7,
            challenge: b"challenge".to_vec(),
        };
        for (name, response) in [
            ("wrong", "0x35524f3f6d24a5b27d3a2ff77c7c5060"),
            ("initiator", "0x00000000000000000000000000000000"),
        ] {
            let mut exchange = ChapExchange {
                credentials: credentials.clone(),
                state: state.clone(),
            };
            assert_eq!(
                exchange.verify(name, response),
                Err(ChapError::AuthenticationFailed)
            );
        }
        let oversized = format!("0x{}", "00".repeat(MAX_CHAP_BINARY_LENGTH + 1));
        assert_eq!(
            decode_binary(&oversized),
            Err(ChapError::InvalidBinaryValue)
        );
    }

    #[test]
    fn challenge_uses_algorithm_five_and_bounded_random_bytes() {
        let credentials =
            Arc::new(ChapCredentials::new("initiator".to_owned(), b"secret".to_vec()).unwrap());
        let mut exchange = ChapExchange::new(credentials);
        let response = exchange.challenge("7,5").unwrap();
        assert_eq!(response.get("CHAP_A"), Some("5"));
        assert_eq!(response.get("CHAP_C").unwrap().len(), 66);
        assert_eq!(exchange.challenge("5"), Err(ChapError::UnexpectedMessage));
    }
}
