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
                arr.iter().map(|e| e.to_string()).collect::<Vec<String>>().join(", ")
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

    // ------------------------------------------------------------------
    // IP Lists
    // ------------------------------------------------------------------

    pub async fn find_ip_list_id(&self, account_id: &str, list_name: &str) -> Result<Option<String>, String> {
        let url = format!("https://api.cloudflare.com/client/v4/accounts/{}/rules/lists", account_id);
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
            for list in result {
                if list.get("name").and_then(|v| v.as_str()) == Some(list_name) {
                    return Ok(list.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()));
                }
            }
        }
        Ok(None)
    }

    pub async fn add_ip_to_list(&self, account_id: &str, list_id: &str, ip: &str, comment: &str) -> Result<bool, String> {
        let url = format!("https://api.cloudflare.com/client/v4/accounts/{}/rules/lists/{}/items", account_id, list_id);
        let items = if comment.is_empty() {
            json!([{"ip": ip}])
        } else {
            json!([{"ip": ip, "comment": comment}])
        };
        let req = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&items);
        let res = self.auth_headers(req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error: {}", text));
        }

        let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        Ok(json.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    pub async fn remove_ip_from_list(&self, account_id: &str, list_id: &str, ip: &str) -> Result<bool, String> {
        // First, find the item ID for this IP
        let url = format!("https://api.cloudflare.com/client/v4/accounts/{}/rules/lists/{}/items", account_id, list_id);
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
        let item_id = if let Some(result) = json.get("result").and_then(|v| v.as_array()) {
            result.iter()
                .find(|item| item.get("ip").and_then(|v| v.as_str()) == Some(ip))
                .and_then(|item| item.get("id").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
        } else {
            None
        };

        let item_id = item_id.ok_or_else(|| format!("IP {} not found in list", ip))?;

        let delete_url = format!("https://api.cloudflare.com/client/v4/accounts/{}/rules/lists/{}/items", account_id, list_id);
        let body = json!({"items": [{"id": item_id}]});
        let req = self.client
            .delete(&delete_url)
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
        Ok(json.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    pub async fn replace_ip_list_items(&self, account_id: &str, list_id: &str, ip: &str, comment: &str) -> Result<bool, String> {
        let url = format!("https://api.cloudflare.com/client/v4/accounts/{}/rules/lists/{}/items", account_id, list_id);
        let items = if comment.is_empty() {
            json!([{"ip": ip}])
        } else {
            json!([{"ip": ip, "comment": comment}])
        };
        let req = self.client
            .put(&url)
            .header("Content-Type", "application/json")
            .json(&items);
        let res = self.auth_headers(req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error: {}", text));
        }

        let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        Ok(json.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    /// Adds an IP to the list. If the IP already exists, does nothing.
    /// If a comment is provided and an existing entry has the same comment but
    /// a different IP, deletes the old entry and adds the new one.
    /// Returns (did_something, success).
    pub async fn add_or_update_ip_by_comment(
        &self,
        account_id: &str,
        list_id: &str,
        ip: &str,
        comment: &str,
    ) -> Result<(bool, bool), String> {
        // Fetch all items first
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/rules/lists/{}/items",
            account_id, list_id
        );
        let req = self.client.get(&url);
        let res = self.auth_headers(req)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            return Err(format!("Cloudflare API error listing items: {}", text));
        }

        let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        let items = json.get("result").and_then(|v| v.as_array());

        // If the IP already exists anywhere in the list, do nothing
        let ip_exists = items.map_or(false, |arr| {
            arr.iter().any(|item| {
                item.get("ip").and_then(|v| v.as_str()) == Some(ip)
            })
        });
        if ip_exists {
            return Ok((false, true));
        }

        // If a comment is provided, check for an existing entry with the same comment
        if !comment.is_empty() {
            let existing = items.and_then(|arr| {
                arr.iter().find(|item| {
                    item.get("comment").and_then(|v| v.as_str()) == Some(comment)
                })
            });

            if let Some(item) = existing {
                let item_id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if item_id.is_empty() {
                    return Err("Found matching comment but item has no ID".to_string());
                }

                // Delete old item, then add new one
                let delete_url = format!(
                    "https://api.cloudflare.com/client/v4/accounts/{}/rules/lists/{}/items",
                    account_id, list_id
                );
                let body = json!({"items": [{"id": item_id}]});
                let req = self.client
                    .delete(&delete_url)
                    .header("Content-Type", "application/json")
                    .json(&body);
                let res = self.auth_headers(req)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;

                if !res.status().is_success() {
                    let text = res.text().await.unwrap_or_default();
                    return Err(format!("Cloudflare API error deleting old item: {}", text));
                }

                let del_json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
                if !del_json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    return Err("Failed to delete old item before updating".to_string());
                }

                let ok = self.add_ip_to_list(account_id, list_id, ip, comment).await?;
                return Ok((true, ok));
            }
        }

        // No matching IP or comment — add new item
        let ok = self.add_ip_to_list(account_id, list_id, ip, comment).await?;
        Ok((true, ok))
    }
}
