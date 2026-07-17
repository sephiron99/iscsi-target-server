//! Target Session 식별, connection binding과 자원 상한.

use std::collections::HashMap;

use crate::login::{IscsiName, SessionType};
use crate::serial::{SequenceError, SequenceState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    pub isid: [u8; 6],
    pub tsih: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionIdentity {
    pub initiator_name: IscsiName,
    pub target_name: Option<IscsiName>,
    pub session_type: SessionType,
    pub isid: [u8; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRegistryLimits {
    pub max_sessions: usize,
    pub max_connections_per_session: usize,
    pub command_window: u32,
}

impl Default for SessionRegistryLimits {
    fn default() -> Self {
        Self {
            max_sessions: 128,
            max_connections_per_session: 1,
            command_window: 32,
        }
    }
}

#[derive(Debug)]
pub struct Session {
    id: SessionId,
    identity: SessionIdentity,
    connections: HashMap<u16, u64>,
    sequence: SequenceState,
}

impl Session {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn identity(&self) -> &SessionIdentity {
        &self.identity
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn sequence(&self) -> &SequenceState {
        &self.sequence
    }

    pub fn sequence_mut(&mut self) -> &mut SequenceState {
        &mut self.sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id: SessionId,
    pub cid: u16,
    pub connection_token: u64,
    pub reinstated_session: bool,
    pub reinstated_connection: bool,
}

#[derive(Debug)]
pub struct SessionRegistry {
    limits: SessionRegistryLimits,
    sessions: HashMap<SessionId, Session>,
    identity_index: HashMap<SessionIdentity, SessionId>,
    next_tsih: u16,
    next_connection_token: u64,
}

impl SessionRegistry {
    pub fn new(limits: SessionRegistryLimits) -> Result<Self, SessionError> {
        if limits.max_sessions == 0
            || limits.max_connections_per_session == 0
            || limits.command_window == 0
            || limits.command_window >= (1 << 31)
        {
            return Err(SessionError::InvalidLimits);
        }
        Ok(Self {
            limits,
            sessions: HashMap::new(),
            identity_index: HashMap::new(),
            next_tsih: 1,
            next_connection_token: 1,
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn get_mut(&mut self, id: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(&id)
    }

    pub fn open_connection(
        &mut self,
        identity: SessionIdentity,
        requested_tsih: u16,
        cid: u16,
        initial_cmd_sn: u32,
        initial_stat_sn: u32,
    ) -> Result<SessionBinding, SessionError> {
        if requested_tsih == 0 {
            return self.create_or_reinstate_session(
                identity,
                cid,
                initial_cmd_sn,
                initial_stat_sn,
            );
        }

        let id = SessionId {
            isid: identity.isid,
            tsih: requested_tsih,
        };
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SessionError::NotFound(id))?;
        if session.identity != identity {
            return Err(SessionError::IdentityMismatch);
        }
        let reinstated_connection = session.connections.contains_key(&cid);
        if !reinstated_connection
            && session.connections.len() >= self.limits.max_connections_per_session
        {
            return Err(SessionError::ConnectionLimit {
                max: self.limits.max_connections_per_session,
            });
        }
        let token = allocate_token(&mut self.next_connection_token);
        session.connections.insert(cid, token);
        Ok(SessionBinding {
            session_id: id,
            cid,
            connection_token: token,
            reinstated_session: false,
            reinstated_connection,
        })
    }

    pub fn close_connection(&mut self, binding: SessionBinding) -> bool {
        let Some(session) = self.sessions.get_mut(&binding.session_id) else {
            return false;
        };
        if session.connections.get(&binding.cid) != Some(&binding.connection_token) {
            return false;
        }
        session.connections.remove(&binding.cid);
        true
    }

    pub fn close_session(&mut self, id: SessionId) -> bool {
        let Some(session) = self.sessions.remove(&id) else {
            return false;
        };
        self.identity_index.remove(&session.identity);
        true
    }

    fn create_or_reinstate_session(
        &mut self,
        identity: SessionIdentity,
        cid: u16,
        initial_cmd_sn: u32,
        initial_stat_sn: u32,
    ) -> Result<SessionBinding, SessionError> {
        let old_id = self.identity_index.get(&identity).copied();
        let reinstated_session = old_id.is_some();
        if old_id.is_none() && self.sessions.len() >= self.limits.max_sessions {
            return Err(SessionError::SessionLimit {
                max: self.limits.max_sessions,
            });
        }
        if let Some(id) = old_id {
            self.sessions.remove(&id);
            self.identity_index.remove(&identity);
        }

        let tsih = self.allocate_tsih()?;
        let id = SessionId {
            isid: identity.isid,
            tsih,
        };
        let token = allocate_token(&mut self.next_connection_token);
        let mut connections = HashMap::new();
        connections.insert(cid, token);
        let sequence =
            SequenceState::new(initial_cmd_sn, initial_stat_sn, self.limits.command_window)?;
        self.sessions.insert(
            id,
            Session {
                id,
                identity: identity.clone(),
                connections,
                sequence,
            },
        );
        self.identity_index.insert(identity, id);
        Ok(SessionBinding {
            session_id: id,
            cid,
            connection_token: token,
            reinstated_session,
            reinstated_connection: false,
        })
    }

    fn allocate_tsih(&mut self) -> Result<u16, SessionError> {
        for _ in 0..u16::MAX {
            let candidate = self.next_tsih.max(1);
            self.next_tsih = candidate.wrapping_add(1).max(1);
            if !self.sessions.keys().any(|id| id.tsih == candidate) {
                return Ok(candidate);
            }
        }
        Err(SessionError::TsihExhausted)
    }
}

fn allocate_token(next: &mut u64) -> u64 {
    let token = *next;
    *next = next.wrapping_add(1).max(1);
    token
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Session registry limits are invalid")]
    InvalidLimits,
    #[error("Session limit {max} reached")]
    SessionLimit { max: usize },
    #[error("connection limit {max} reached")]
    ConnectionLimit { max: usize },
    #[error("Session {0:?} was not found")]
    NotFound(SessionId),
    #[error("Session identity does not match ISID/TSIH")]
    IdentityMismatch,
    #[error("all non-zero TSIH values are in use")]
    TsihExhausted,
    #[error(transparent)]
    Sequence(#[from] SequenceError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(host: &str, isid: [u8; 6]) -> SessionIdentity {
        SessionIdentity {
            initiator_name: IscsiName::parse(host).unwrap(),
            target_name: Some(IscsiName::parse("iqn.2024-01.com.example:target").unwrap()),
            session_type: SessionType::Normal,
            isid,
        }
    }

    #[test]
    fn creates_adds_and_reinstates_connections_without_stale_close() {
        let mut registry = SessionRegistry::new(SessionRegistryLimits {
            max_sessions: 2,
            max_connections_per_session: 2,
            command_window: 4,
        })
        .unwrap();
        let identity = identity("iqn.2024-01.com.example:host", [1, 2, 3, 4, 5, 6]);
        let first = registry
            .open_connection(identity.clone(), 0, 7, 10, 20)
            .unwrap();
        assert_ne!(first.session_id.tsih, 0);
        let second = registry
            .open_connection(identity.clone(), first.session_id.tsih, 8, 10, 20)
            .unwrap();
        assert_eq!(
            registry.get(first.session_id).unwrap().connection_count(),
            2
        );
        let replacement = registry
            .open_connection(identity.clone(), first.session_id.tsih, 7, 10, 20)
            .unwrap();
        assert!(replacement.reinstated_connection);
        assert!(!registry.close_connection(first));
        assert!(registry.close_connection(replacement));
        assert!(registry.close_connection(second));

        let reinstated = registry.open_connection(identity, 0, 1, 30, 40).unwrap();
        assert!(reinstated.reinstated_session);
        assert_ne!(reinstated.session_id, first.session_id);
        assert!(registry.get(first.session_id).is_none());
    }

    #[test]
    fn enforces_session_and_connection_limits_and_identity_matching() {
        let mut registry = SessionRegistry::new(SessionRegistryLimits {
            max_sessions: 1,
            max_connections_per_session: 1,
            command_window: 1,
        })
        .unwrap();
        let first_identity = identity("iqn.2024-01.com.example:host1", [1; 6]);
        let first = registry
            .open_connection(first_identity.clone(), 0, 1, 0, 0)
            .unwrap();
        assert!(matches!(
            registry.open_connection(first_identity.clone(), first.session_id.tsih, 2, 0, 0),
            Err(SessionError::ConnectionLimit { max: 1 })
        ));
        assert!(matches!(
            registry.open_connection(
                identity("iqn.2024-01.com.example:host2", [2; 6]),
                0,
                1,
                0,
                0
            ),
            Err(SessionError::SessionLimit { max: 1 })
        ));
        assert!(matches!(
            registry.open_connection(
                identity("iqn.2024-01.com.example:other", [1; 6]),
                first.session_id.tsih,
                1,
                0,
                0
            ),
            Err(SessionError::IdentityMismatch)
        ));
    }
}
