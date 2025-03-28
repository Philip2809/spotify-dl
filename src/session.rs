use anyhow::Result;
use librespot::core::cache::Cache;
use librespot::core::config::SessionConfig;
use librespot::core::session::Session;
use librespot::discovery::Credentials;

pub async fn create_session(token: Option<String>) -> Result<Session> {
    let credentials_store = dirs::home_dir().map(|p| p.join(".spotify-dl"));
    let cache = Cache::new(credentials_store, None, None, None)?;

    let session_config = SessionConfig::default();
    let credentials = get_credentials(token, &cache);

    cache.save_credentials(&credentials);

    let session = Session::new(session_config, None);
    if let Err(e) = session.connect(credentials, true).await {
        println!("Error connecting: {}", e);
        return Err(e.into());
    }

    Ok(session)
}

fn prompt_token() -> Result<String> {
    tracing::info!("Spotify access token was not provided. Please enter your Spotify access token below");
    rpassword::prompt_password("Access token: ").map_err(|e| e.into())
}

fn get_credentials(token: Option<String>, cache: &Cache) -> Credentials {
    match token {
        Some(token) => Credentials::with_access_token(token),
        _ => cache.credentials().unwrap_or_else(|| {
            tracing::warn!("No credentials found in cache");
            Credentials::with_access_token(
                prompt_token().unwrap_or_else(|_| panic!("Failed to get access token")),
            )
        }),
    }
}
