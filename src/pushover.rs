use reqwest;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct PushoverPayload {
    token: String,
    user: String,
    title: String,
    message: String,
    priority: i8,
    sound: String,
}

pub struct PushoverClient {
    app_token: String,
    user_key: String,
    client: reqwest::Client,
}

impl PushoverClient {
    pub fn new(app_token: String, user_key: String) -> Self {
        Self {
            app_token,
            user_key,
            client: reqwest::Client::new(),
        }
    }

    pub async fn send(
        &self,
        title: &str,
        message: &str,
        priority: i8,
        sound: &str,
    ) -> Result<(), String> {
        let payload = PushoverPayload {
            token: self.app_token.clone(),
            user: self.user_key.clone(),
            title: title.to_string(),
            message: message.to_string(),
            priority,
            sound: sound.to_string(),
        };
        let res = self
            .client
            .post("https://api.pushover.net/1/messages.json")
            .form(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("Pushover API error: {}", res.status()))
        }
    }
}
