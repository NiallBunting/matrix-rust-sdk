use anyhow::Result;
use clap::Parser;
use futures_util::{pin_mut, StreamExt};
use matrix_sdk::{config::SyncSettings, encryption::backups::BackupState, Client};
use tokio::io::{AsyncBufReadExt, BufReader};
use url::Url;
use zeroize::Zeroize;

/// A command line example showcasing how the encryption recovery works in the
/// Matrix Rust SDK.
#[derive(Parser, Debug)]
struct Cli {
    /// The homeserver to connect to.
    #[clap(value_parser)]
    homeserver: Url,

    /// The user ID that should be used to restore the session.
    #[clap(value_parser)]
    user_name: String,

    /// The password that should be used for the login.
    #[clap(value_parser)]
    password: String,

    /// Set the proxy that should be used for the connection.
    #[clap(short, long)]
    proxy: Option<Url>,

    /// Enable verbose logging output.
    #[clap(short, long, action)]
    verbose: bool,
}

#[derive(Parser, Debug)]
#[command(no_binary_name = true)]
enum Command {
    /// Disable backups and recovery, whatever the later means.
    Disable,
    /// Enable backups, can't enable secret storage unless we enter the secret
    /// storage key, should we generate a new one?
    Enable,
    /// Change the recovery key, we generate a new one and present the base58
    /// string to the user.
    ChangeRecoveryKey {
        /// The passphrase, which can be used to recover, in addition to the
        /// recovery key.
        #[clap(long, action)]
        passphrase: Option<String>,
    },
    /// Logout, if recovery isn't enabled, ask the user if they want to do so
    /// now.
    Logout,
    Recover {
        /// The recovery key, AKA the secret storage key, this key will be used
        /// to open the secret-store. Not to be confused with the
        /// Recovery key from the spec.
        #[clap(long, action)]
        recovery_key: String,
    },
}

async fn recover(client: &Client, recovery_key: &str) -> Result<()> {
    // You see how this name isn't really fitting?
    client.encryption().recovery().fix_recovery_issues(recovery_key).await?;

    let status = client
        .encryption()
        .cross_signing_status()
        .await
        .expect("We should be able to get our cross-signing status");

    if status.is_complete() {
        println!("Successfully imported all the cross-signing keys");
    } else {
        eprintln!("Couldn't import all the cross-signing keys: {status:?}");
    }

    Ok(())
}

async fn login(cli: &Cli) -> Result<Client> {
    let builder = Client::builder().homeserver_url(&cli.homeserver);

    let builder = if let Some(proxy) = &cli.proxy { builder.proxy(proxy) } else { builder };

    let client = builder.build().await?;

    client
        .matrix_auth()
        .login_username(&cli.user_name, &cli.password)
        .initial_device_display_name("rust-sdk")
        .await?;

    Ok(client)
}

async fn listen_for_backup_state_changes(client: Client) {
    let stream = client.encryption().backups().state_stream();
    pin_mut!(stream);

    while let Some(state) = stream.next().await {
        match state {
            BackupState::Unknown => (),
            BackupState::Enabling => println!("Trying to enable backups"),
            BackupState::Resuming => println!("Trying to resume backups"),
            BackupState::Enabled => println!("Successfully enabled backups"),
            BackupState::Downloading => println!("Downloading the room keys from the backup"),
            BackupState::Disabling => println!("Disabling the backup"),
            BackupState::Disabled => println!("Backup successfully disabled"),
            BackupState::Creating => println!("Trying to create a new backup"),
        }
    }
}

async fn logout(client: &Client) -> Result<()> {
    let recovery = client.encryption().recovery();
    let enable_backup = recovery.enable().wait_for_backups_upload().create_new_backup();

    let progress = enable_backup.subscribe_to_progress();

    let task = tokio::spawn(async move {
        pin_mut!(progress);

        while let Some(update) = progress.next().await {
            println!("Hello world {update:?}");
        }
    });

    let recovery_key = enable_backup.await?;
    println!("Successfully created a recovery key: `{recovery_key}`.");

    task.abort();

    Ok(())
}

async fn enable(client: &Client) -> Result<()> {
    let recovery = client.encryption().recovery();
    let enable_backup = recovery.enable();

    let recovery_key = enable_backup.await?;
    println!("Successfully enabled recovery, recovery key: `{recovery_key}`.");

    Ok(())
}

async fn disable(client: &Client) -> Result<()> {
    client.encryption().recovery().disable().await?;

    println!("Successfully disable recovery.");

    Ok(())
}

async fn reset_key(client: &Client, passphrase: Option<&str>) -> Result<()> {
    if let Some(mut recovery_key) = client.encryption().recovery().reset_key(passphrase).await? {
        println!("Successfully changed the recovery key, new key: `{recovery_key}`.");
        recovery_key.zeroize();
    } else {
        println!("Could not change the recovery key as we don't have access to all the secrets.")
    }

    Ok(())
}

async fn run_command(client: &Client, command: Command) -> Result<()> {
    match command {
        Command::Disable => disable(client).await,
        Command::Enable => enable(client).await,
        Command::ChangeRecoveryKey { mut passphrase } => {
            let ret = reset_key(client, passphrase.as_deref()).await;
            passphrase.zeroize();
            ret
        }
        Command::Recover { mut recovery_key } => {
            let ret = recover(client, &recovery_key).await;
            recovery_key.zeroize();

            ret
        }
        Command::Logout => logout(client).await,
    }
}

async fn get_command(client: Client) -> Result<()> {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);

    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.split_whitespace();

        match Command::try_parse_from(line) {
            Ok(command) => run_command(&client, command).await?,
            Err(e) => println!("{e}"),
        }
    }

    Ok(())
}

async fn sync(client: Client) {
    loop {
        if let Err(e) = client.sync(SyncSettings::new()).await {
            eprintln!("Error syncing, what the fuck is going on with this synapse {e:?}")
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt::init();
    }

    let client = login(&cli).await?;

    client.sync_once(Default::default()).await?;

    let _task = tokio::spawn({
        let client = client.to_owned();
        async move { listen_for_backup_state_changes(client.to_owned()).await }
    });

    let _sync_task = tokio::spawn({
        let client = client.to_owned();
        async move { sync(client).await }
    });

    get_command(client).await?;

    Ok(())
}
