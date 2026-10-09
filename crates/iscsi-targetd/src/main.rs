//! `iscsi-targetd` — 설정 파일 기반 iSCSI Target server. 콘솔에서 foreground로 실행한다.
//!
//! stdout에는 기계가 읽는 상태 줄(`listening <address>`)과 `--check` 결과만 쓰고,
//! 구조화된 로그는 전부 stderr로 보낸다.

use std::process::ExitCode;

use iscsi_target_server::server::{Server, ServerError};
use iscsi_target_server::{ServerConfig, TargetServiceError};

mod cli;

use cli::CliCommand;

fn main() -> ExitCode {
    let options = match cli::parse_arguments(std::env::args().skip(1)) {
        Ok(CliCommand::Help) => {
            print!("{}", cli::USAGE);
            return ExitCode::SUCCESS;
        }
        Ok(CliCommand::Run(options)) => options,
        Err(error) => {
            eprintln!("argument error: {error}\n\n{}", cli::USAGE);
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = tracing_subscriber::fmt()
        .with_max_level(options.log_level.tracing_level())
        .with_writer(std::io::stderr)
        .try_init()
    {
        eprintln!("failed to initialize logging: {error}");
        return ExitCode::FAILURE;
    }

    let config = match ServerConfig::load_from_file(&options.config_path) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(path = %options.config_path.display(), %error, "could not load the configuration");
            return ExitCode::FAILURE;
        }
    };
    if options.check_only {
        println!("configuration is valid: {}", options.config_path.display());
        return ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "could not create the Tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(async {
        let server = Server::bind(&config).await?;
        let address = server
            .local_addr()
            .map_err(TargetServiceError::from)
            .map_err(ServerError::from)?;
        println!("listening {address}");
        tracing::info!(%address, "Target service started");
        server
            .run(async {
                if let Err(error) = cli::shutdown_signal().await {
                    tracing::error!(%error, "could not register the signal handler; shutting down");
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
                "shut down cleanly"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!(%error, "exiting on a server error");
            ExitCode::FAILURE
        }
    }
}
