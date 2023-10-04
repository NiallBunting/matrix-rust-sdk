use anyhow::Result;
use clap::{Parser, Subcommand};
use matrix_sdk::{
    config::SyncSettings,
    encryption::secret_storage::SecretStore,
    matrix_auth::{MatrixSession, MatrixSessionTokens},
    ruma::{events::secret::request::SecretName, OwnedDeviceId, OwnedUserId},
    AuthSession, Client, SessionMeta,
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

    if client.encryption().backups().is_enabled().await {
        println!("Successfully imported the backup recovery key and enabled backups");
    } else {
        eprintln!("Couldn't import the backup recovery key");
    }

    Ok(())
}

async fn login(cli: &Cli) -> Result<Client> {
    let builder = Client::builder().homeserver_url(cli.homeserver.to_owned());

    let builder = if let Some(proxy) = &cli.proxy { builder.proxy(proxy) } else { builder };

    let client = builder.build().await?;

    client
        .matrix_auth()
        .login_username(&cli.user_name, &cli.password)
        .initial_device_display_name("rust-sdk")
        .await?;

    Ok(client)
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

    import_known_secrets(&client, secret_store).await?;

    loop {
        if let Err(e) = client.sync(SyncSettings::new()).await {
            eprintln!("Error syncing, what the fuck is going on with this synapse {e:?}")
        }
    }

    Ok(())
}
