use serde_json::json;

pub struct CloudflareClient {
    token: String,
    email: Option<String>,
    client: reqwest::Client,
}

impl CloudflareClient {
    /// Create with API Token auth (Bearer).
    pub fn with_token(token: String) -> Self {
        Self {
            token,
            email: None,
            client: reqwest::Client::new(),
        }
    }

    /// Create with Global API Key auth (X-Auth-Email + X-Auth-Key).
    pub fn with_global_key(email: String, key: String) -> Self {
        Self {
            token: key,
            email: Some(email),
            client: reqwest::Client::new(),
        }
    }

    fn auth_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref email) = self.email {
            req.header("X-Auth-Email", email.clone())
               .header("X-Auth-Key", self.token.clone())
        } else {
            req.header("Authorization", format!("Bearer {}", self.token))
        }
    }

    pub async fn update_dns_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
        proxied: bool,
        ttl: u32,
    ) -> Result<bool, String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            zone_id, record_id
        );
        let body = json!({
            "type": record_type,
            "name": name,
            "content": content,
            "ttl": ttl,
            "proxied": proxied,
        });
        let req = self.client
            .put(&url)
            .header("Content-Type", "application/json")
            .json(&body);
        let res = self.auth_headers(req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error: {}", text));
        }

        let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        if json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(true)
        } else {
            let errors = json.get("errors").and_then(|v| v.as_array()).map(|arr| {
                arr.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(", ")
            }).unwrap_or_else(|| "Unknown error".to_string());
            Err(format!("Cloudflare API returned errors: {}", errors))
        }
    }

    pub async fn find_record_id(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> Result<Option<String>, String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type={}&name={}",
            zone_id, record_type, name
        );
        let req = self.client.get(&url);
        let res = self.auth_headers(req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error: {}", text));
        }

        let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        if let Some(result) = json.get("result").and_then(|v| v.as_array()) {
            if let Some(record) = result.first() {
                return Ok(record.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()));
            }
        }
        Ok(None)
    }
}
