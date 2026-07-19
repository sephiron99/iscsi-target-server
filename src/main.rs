//! `iscsi-targetd` — 설정 파일 기반 headless iSCSI Target daemon.
//!
//! stdout에는 기계가 읽는 상태 줄(`listening <address>`)과 `--check` 결과만 쓰고,
//! 구조화된 로그는 전부 stderr로 보낸다.

use std::process::ExitCode;

use pdu::daemon::{self, CliCommand, Daemon};
use pdu::{DaemonConfig, TargetServiceError};

fn main() -> ExitCode {
    let options = match daemon::parse_arguments(std::env::args().skip(1)) {
        Ok(CliCommand::Help) => {
            print!("{}", daemon::USAGE);
            return ExitCode::SUCCESS;
        }
        Ok(CliCommand::Run(options)) => options,
        Err(error) => {
            eprintln!("인자 오류: {error}\n\n{}", daemon::USAGE);
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = tracing_subscriber::fmt()
        .with_max_level(options.log_level.tracing_level())
        .with_writer(std::io::stderr)
        .try_init()
    {
        eprintln!("로그 초기화 실패: {error}");
        return ExitCode::FAILURE;
    }

    let config = match DaemonConfig::load_from_file(&options.config_path) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(path = %options.config_path.display(), %error, "설정을 읽지 못했다");
            return ExitCode::FAILURE;
        }
    };
    if options.check_only {
        println!("설정 검증 성공: {}", options.config_path.display());
        return ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "Tokio runtime을 만들지 못했다");
            return ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(async {
        let daemon = Daemon::bind(&config).await?;
        let address = daemon
            .local_addr()
            .map_err(TargetServiceError::from)
            .map_err(daemon::DaemonError::from)?;
        println!("listening {address}");
        tracing::info!(%address, "Target service 시작");
        daemon
            .run(async {
                if let Err(error) = daemon::shutdown_signal().await {
                    tracing::error!(%error, "signal handler를 등록하지 못해 종료한다");
                }
            })
            .await
    });

    match result {
        Ok(summary) => {
            tracing::info!(
                accepted = summary.accepted_connections,
                completed = summary.completed_connections,
                failed = summary.failed_connections,
                aborted = summary.aborted_connections,
                "정상 종료"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "daemon 오류로 종료한다");
            ExitCode::FAILURE
        }
    }
}
