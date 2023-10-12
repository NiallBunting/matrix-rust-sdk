use anyhow::Result;
use clap::Parser;
use futures_util::{pin_mut, StreamExt};
use matrix_sdk::{
    config::SyncSettings,
    encryption::{backups::BackupState, secret_storage::SecretStore},
    Client,
};
use url::Url;

/// A command line example showcasing how the secret storage support works in
/// the Matrix Rust SDK.
///
/// Secret storage is an account data backed encrypted key/value store. You can
/// put or get secrets from the store.
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

    /// The secret storage key, this key will be used to open the secret-store.
    #[clap(long, action)]
    secret_store_key: String,
}

async fn import_known_secrets(client: &Client, secret_store: SecretStore) -> Result<()> {
    secret_store.import_secrets().await?;

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

    let secret_store = client.encryption().open_secret_store(&cli.secret_store_key).await?;

    let _task = tokio::spawn({
        let client = client.to_owned();
        async move { listen_for_backup_state_changes(client.to_owned()).await }
    });

    import_known_secrets(&client, secret_store).await?;

    loop {
        if let Err(e) = client.sync(SyncSettings::new()).await {
            eprintln!("Error syncing, what the fuck is going on with this synapse {e:?}")
        }
    }
}
