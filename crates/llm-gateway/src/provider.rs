use crate::{Error, Provider, Result, send};
use client::llm::MAX_OUTPUT_BYTES;
use futures::AsyncWrite;
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde_json::{Value, json};
use wire::protocol::{LlmFrame, LlmRequest, LlmUsage, MAX_FRAME};

pub struct Backend {
    client: Client,
    url: Url,
    authorization: Option<HeaderValue>,
}
impl Backend {
    pub fn new(config: &Provider) -> Result<Self> {
        let url = Url::parse(&config.url).map_err(|_| Error::Invalid("invalid provider URL"))?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if (!url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some())
            || !(url.scheme() == "https"
                || (url.scheme() == "http" && loopback && config.self_hosted))
            || (config.sensitive && !config.self_hosted)
            || config.models.is_empty()
            || config.context_tokens == 0
        {
            return Err(Error::Invalid("invalid provider security configuration"));
        }
        let authorization = config
            .key_env
            .as_ref()
            .map(|name| {
                let key = std::env::var(name)
                    .map_err(|_| Error::Invalid("provider key environment variable missing"))?;
                if key.trim().is_empty() {
                    return Err(Error::Invalid("provider key is empty"));
                }
                let mut value = HeaderValue::from_str(&format!("Bearer {key}"))
                    .map_err(|_| Error::Invalid("invalid provider key"))?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        if authorization.is_none() && !config.self_hosted {
            return Err(Error::Invalid("public provider key required"));
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|_| Error::Provider)?;
        Ok(Self {
            client,
            url,
            authorization,
        })
    }
    pub async fn complete(
        &self,
        request: &LlmRequest,
        writer: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(Option<LlmUsage>, bool)> {
        let mut messages = serde_json::to_value(&request.messages)?;
        if !request.attachments.is_empty() {
            let parts: Vec<Value> = request
                .attachments
                .iter()
                .map(|a| {
                    let url = format!("data:{};base64,{}", a.mime, a.data);
                    if a.mime == "application/pdf" {
                        json!({"type":"file","file":{"filename":a.name,"file_data":url}})
                    } else {
                        json!({"type":"image_url","image_url":{"url":url}})
                    }
                })
                .collect();
            messages
                .as_array_mut()
                .ok_or(Error::Invalid("invalid messages"))?
                .push(json!({"role":"user","content":parts}));
        }
        let mut call = self.client.post(self.url.clone()).json(&json!({
            "model": request.model, "messages": messages,
            "max_tokens": request.max_tokens, "stream": true,
            "stream_options": {"include_usage": true}, "n": 1,
        }));
        if let Some(key) = &self.authorization {
            call = call.header(AUTHORIZATION, key.clone());
        }
        let mut response = call.send().await.map_err(|_| Error::Provider)?;
        if !response.status().is_success()
            || !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim() == "text/event-stream")
                })
        {
            return Err(Error::Provider);
        }
        let mut buffer = Vec::new();
        let mut event = String::new();
        let mut content = String::new();
        let mut usage = None;
        let mut finished = false;
        let mut truncated = false;
        let mut total = 0usize;
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Provider)? {
            total = total.checked_add(chunk.len()).ok_or(Error::Provider)?;
            if total > MAX_OUTPUT_BYTES * 8 {
                return Err(Error::Invalid("provider response too large"));
            }
            buffer.extend_from_slice(&chunk);
            while let Some(end) = buffer.iter().position(|b| *b == b'\n') {
                if end > MAX_FRAME {
                    return Err(Error::Invalid("provider event too large"));
                }
                let raw: Vec<_> = buffer.drain(..=end).collect();
                let line = std::str::from_utf8(&raw)
                    .map_err(|_| Error::Provider)?
                    .trim_end_matches(['\r', '\n']);
                if let Some(data) = line.strip_prefix("data:") {
                    if !event.is_empty() {
                        event.push('\n');
                    }
                    event.push_str(data.strip_prefix(' ').unwrap_or(data));
                    if event.len() > MAX_FRAME {
                        return Err(Error::Invalid("provider event too large"));
                    }
                } else if line.is_empty() && !event.is_empty() {
                    if event == "[DONE]" {
                        if !finished {
                            return Err(Error::Invalid("provider ended without finish reason"));
                        }
                        if !request.stream {
                            delta(writer, &content).await?;
                        }
                        return Ok((usage, truncated));
                    }
                    let value: Value = serde_json::from_str(&event).map_err(|_| Error::Provider)?;
                    event.clear();
                    if value.get("error").is_some() {
                        return Err(Error::Provider);
                    }
                    if let Some(value) = value.get("usage").filter(|v| !v.is_null()) {
                        let parsed: LlmUsage =
                            serde_json::from_value(value.clone()).map_err(|_| Error::Provider)?;
                        if parsed.prompt_tokens.checked_add(parsed.completion_tokens)
                            != Some(parsed.total_tokens)
                            || usage.is_some()
                            || parsed.completion_tokens > u64::from(request.max_tokens)
                        {
                            return Err(Error::Invalid("invalid provider usage"));
                        }
                        usage = Some(parsed);
                    }
                    let choices = value
                        .get("choices")
                        .and_then(Value::as_array)
                        .ok_or(Error::Provider)?;
                    if choices.len() > 1 {
                        return Err(Error::Provider);
                    }
                    if let Some(choice) = choices.first() {
                        if choice["index"].as_u64() != Some(0) || finished {
                            return Err(Error::Provider);
                        }
                        if let Some(text) = choice["delta"]["content"].as_str() {
                            if content.len().saturating_add(text.len()) > MAX_OUTPUT_BYTES {
                                return Err(Error::Invalid("output too large"));
                            }
                            content.push_str(text);
                            if request.stream {
                                delta(writer, text).await?;
                            }
                        }
                        if let Some(reason) = choice["finish_reason"].as_str() {
                            if !matches!(reason, "stop" | "length" | "content_filter") {
                                return Err(Error::Invalid("unsupported provider finish reason"));
                            }
                            finished = true;
                            truncated = reason != "stop";
                        }
                    }
                }
            }
            if buffer.len() > MAX_FRAME {
                return Err(Error::Invalid("provider event too large"));
            }
        }
        Err(Error::Invalid("provider stream interrupted"))
    }
}
async fn delta(writer: &mut (impl AsyncWrite + Unpin), mut text: &str) -> Result<()> {
    const DELTA_BYTES: usize = 4096;
    while !text.is_empty() {
        let mut end = text.len().min(DELTA_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        send(
            writer,
            &LlmFrame::Delta {
                content: text[..end].into(),
            },
        )
        .await?;
        text = &text[end..];
    }
    Ok(())
}
