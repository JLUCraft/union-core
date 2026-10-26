use crate::{
    ApiDialect, Authentication, Completion, Error, MAX_OUTPUT_BYTES, Provider, Result, send,
};
use futures::AsyncWrite;
use protocol::{LlmFrame, LlmRequest, LlmUsage, MAX_FRAME};
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde_json::{Value, json};

const MAX_RESPONSE_BYTES: usize = MAX_OUTPUT_BYTES * 8;
const DELTA_BYTES: usize = 4096;
const MAX_SECRET_BYTES: u64 = 8192;
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub struct Backend {
    client: Client,
    url: Url,
    headers: HeaderMap,
    protocol: ApiDialect,
    context_tokens: u64,
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
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || config.models.is_empty()
            || config.context_tokens == 0
            || (config.key_env.is_some() && config.key_file.is_some())
        {
            return Err(Error::Invalid("invalid provider configuration"));
        }
        let key = match (&config.key_env, &config.key_file) {
            (Some(name), None) => Some(
                std::env::var(name)
                    .map_err(|_| Error::Invalid("provider key environment variable missing"))?,
            ),
            (None, Some(path)) => {
                if std::fs::metadata(path)?.len() > MAX_SECRET_BYTES {
                    return Err(Error::Invalid("provider key file too large"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                        return Err(Error::Invalid("provider key file must be private"));
                    }
                }
                Some(std::fs::read_to_string(path)?.trim().to_owned())
            }
            _ => None,
        };
        let mut headers = HeaderMap::new();
        if let Some(key) = key {
            if key.trim().is_empty() || key.len() as u64 > MAX_SECRET_BYTES {
                return Err(Error::Invalid("invalid provider key"));
            }
            let auth =
                config
                    .authentication
                    .unwrap_or(if config.protocol == ApiDialect::Messages {
                        Authentication::ApiKey
                    } else {
                        Authentication::Bearer
                    });
            let text = if auth == Authentication::Bearer {
                format!("Bearer {key}")
            } else {
                key
            };
            let mut value =
                HeaderValue::from_str(&text).map_err(|_| Error::Invalid("invalid provider key"))?;
            value.set_sensitive(true);
            if auth == Authentication::Bearer {
                headers.insert(AUTHORIZATION, value);
            } else {
                headers.insert("x-api-key", value);
            }
        } else if !loopback {
            return Err(Error::Invalid("provider key required"));
        }
        if config.protocol == ApiDialect::Messages {
            headers.insert(
                "anthropic-version",
                HeaderValue::from_static(ANTHROPIC_VERSION),
            );
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
            headers,
            protocol: config.protocol,
            context_tokens: config.context_tokens,
        })
    }
    pub async fn complete(
        &self,
        request: &LlmRequest,
        writer: &mut (impl AsyncWrite + Unpin),
    ) -> Result<Completion> {
        let body = request_body(self.protocol, request)?;
        let mut response = self
            .client
            .post(self.url.clone())
            .headers(self.headers.clone())
            .json(&body)
            .send()
            .await
            .map_err(|_| Error::Provider)?;
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
        let mut decoder =
            StreamDecoder::new(self.protocol, request.max_tokens, self.context_tokens);
        let mut buffer = Vec::new();
        let mut data = String::new();
        let mut event = String::new();
        let mut total = 0usize;
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Provider)? {
            total = total.checked_add(chunk.len()).ok_or(Error::Provider)?;
            if total > MAX_RESPONSE_BYTES {
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
                if let Some(value) = line.strip_prefix("data:") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(value.strip_prefix(' ').unwrap_or(value));
                    if data.len() > MAX_FRAME {
                        return Err(Error::Invalid("provider event too large"));
                    }
                } else if let Some(value) = line.strip_prefix("event:") {
                    event = value.trim().into();
                } else if line.is_empty() && !data.is_empty() {
                    let start = decoder.content.len();
                    let done = decoder.accept(&event, &data)?;
                    if request.stream {
                        delta(writer, &decoder.content[start..]).await?;
                    }
                    data.clear();
                    event.clear();
                    if done {
                        let completion = decoder.finish()?;
                        if !request.stream {
                            delta(writer, &completion.content).await?;
                        }
                        return Ok(completion);
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

fn request_body(dialect: ApiDialect, request: &LlmRequest) -> Result<Value> {
    let system = request
        .messages
        .iter()
        .filter(|m| m.role == "system")
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    match dialect {
        ApiDialect::ChatCompletions => {
            let mut messages = serde_json::to_value(&request.messages)?;
            if !request.attachments.is_empty() {
                let parts: Vec<_> = request
                    .attachments
                    .iter()
                    .map(|a| {
                        let data = format!("data:{};base64,{}", a.mime, a.data);
                        if a.mime == "application/pdf" {
                            json!({"type":"file","file":{"filename":a.name,"file_data":data}})
                        } else {
                            json!({"type":"image_url","image_url":{"url":data}})
                        }
                    })
                    .collect();
                messages
                    .as_array_mut()
                    .ok_or(Error::Invalid("invalid messages"))?
                    .push(json!({"role":"user","content":parts}));
            }
            Ok(
                json!({"model":request.model,"messages":messages,"max_tokens":request.max_tokens,"stream":true,"stream_options":{"include_usage":true},"n":1}),
            )
        }
        ApiDialect::Responses => {
            let mut input:Vec<Value>=request.messages.iter().filter(|m|m.role!="system").map(|m|json!({"role":m.role,"content":[{"type":if m.role=="assistant" {"output_text"} else {"input_text"},"text":m.content}]})).collect();
            if !request.attachments.is_empty() {
                let content: Vec<_> = request
                    .attachments
                    .iter()
                    .map(|a| {
                        let data = format!("data:{};base64,{}", a.mime, a.data);
                        if a.mime == "application/pdf" {
                            json!({"type":"input_file","filename":a.name,"file_data":data})
                        } else {
                            json!({"type":"input_image","image_url":data})
                        }
                    })
                    .collect();
                input.push(json!({"role":"user","content":content}));
            }
            Ok(
                json!({"model":request.model,"instructions":system,"input":input,"max_output_tokens":request.max_tokens,"stream":true,"store":false}),
            )
        }
        ApiDialect::Messages => {
            let mut messages: Vec<Value> = request
                .messages
                .iter()
                .filter(|m| m.role != "system")
                .map(|m| json!({"role":m.role,"content":[{"type":"text","text":m.content}]}))
                .collect();
            if !request.attachments.is_empty() {
                let content:Vec<_>=request.attachments.iter().map(|a|json!({"type":if a.mime=="application/pdf" {"document"} else {"image"},"source":{"type":"base64","media_type":a.mime,"data":a.data}})).collect();
                messages.push(json!({"role":"user","content":content}));
            }
            Ok(
                json!({"model":request.model,"system":system,"messages":messages,"max_tokens":request.max_tokens,"stream":true}),
            )
        }
    }
}
struct StreamDecoder {
    dialect: ApiDialect,
    content: String,
    usage: Option<LlmUsage>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    finished: bool,
    truncated: bool,
    max_tokens: u64,
    context_tokens: u64,
}
impl StreamDecoder {
    fn new(dialect: ApiDialect, max_tokens: u32, context_tokens: u64) -> Self {
        Self {
            dialect,
            content: String::new(),
            usage: None,
            input_tokens: None,
            output_tokens: None,
            finished: false,
            truncated: false,
            max_tokens: u64::from(max_tokens),
            context_tokens,
        }
    }
    fn append(&mut self, text: &str) -> Result<()> {
        if self.finished || self.content.len().saturating_add(text.len()) > MAX_OUTPUT_BYTES {
            return Err(Error::Invalid("invalid provider output"));
        }
        self.content.push_str(text);
        Ok(())
    }
    fn set_usage(&mut self, value: &Value, input: &str, output: &str) -> Result<()> {
        if self.usage.is_some() {
            return Err(Error::Invalid("duplicate provider usage"));
        }
        let prompt_tokens = value[input].as_u64().ok_or(Error::Provider)?;
        let completion_tokens = value[output].as_u64().ok_or(Error::Provider)?;
        let total_tokens = prompt_tokens
            .checked_add(completion_tokens)
            .ok_or(Error::Provider)?;
        if value
            .get("total_tokens")
            .is_some_and(|v| v.as_u64() != Some(total_tokens))
            || completion_tokens > self.max_tokens
            || total_tokens > self.context_tokens
        {
            return Err(Error::Invalid("invalid provider usage"));
        }
        self.usage = Some(LlmUsage {
            prompt_tokens,
            completion_tokens,
            total_tokens,
        });
        Ok(())
    }
    fn accept(&mut self, event: &str, data: &str) -> Result<bool> {
        if self.dialect == ApiDialect::ChatCompletions && data == "[DONE]" {
            if !self.finished {
                return Err(Error::Invalid("provider ended without finish reason"));
            }
            return Ok(true);
        }
        let value: Value = serde_json::from_str(data).map_err(|_| Error::Provider)?;
        if value.get("error").is_some() || value["type"] == "error" {
            return Err(Error::Provider);
        }
        if self.dialect != ApiDialect::ChatCompletions
            && !event.is_empty()
            && value["type"].as_str() != Some(event)
        {
            return Err(Error::Provider);
        }
        match self.dialect {
            ApiDialect::ChatCompletions => {
                if let Some(usage) = value.get("usage").filter(|v| !v.is_null()) {
                    self.set_usage(usage, "prompt_tokens", "completion_tokens")?;
                }
                let choices = value["choices"].as_array().ok_or(Error::Provider)?;
                if choices.len() > 1 {
                    return Err(Error::Provider);
                }
                if let Some(choice) = choices.first() {
                    if choice["index"].as_u64() != Some(0) || self.finished {
                        return Err(Error::Provider);
                    }
                    if let Some(text) = choice["delta"]["content"].as_str() {
                        self.append(text)?;
                    }
                    if let Some(reason) = choice["finish_reason"].as_str() {
                        if !matches!(reason, "stop" | "length" | "content_filter") {
                            return Err(Error::Provider);
                        }
                        self.finished = true;
                        self.truncated = reason != "stop";
                    }
                }
            }
            ApiDialect::Responses => match value["type"].as_str() {
                Some("response.output_text.delta") => {
                    self.append(value["delta"].as_str().ok_or(Error::Provider)?)?
                }
                Some("response.completed" | "response.incomplete") => {
                    if self.finished {
                        return Err(Error::Provider);
                    }
                    let response = &value["response"];
                    self.set_usage(&response["usage"], "input_tokens", "output_tokens")?;
                    self.finished = true;
                    self.truncated = response["status"] != "completed";
                    return Ok(true);
                }
                Some("response.failed") => return Err(Error::Provider),
                _ => {}
            },
            ApiDialect::Messages => match value["type"].as_str() {
                Some("message_start") => {
                    if self.input_tokens.is_some() {
                        return Err(Error::Provider);
                    }
                    self.input_tokens = Some(
                        value["message"]["usage"]["input_tokens"]
                            .as_u64()
                            .ok_or(Error::Provider)?,
                    );
                }
                Some("content_block_start") => {
                    if value["content_block"]["type"] == "text"
                        && let Some(text) = value["content_block"]["text"].as_str()
                    {
                        self.append(text)?;
                    }
                }
                Some("content_block_delta") if value["delta"]["type"] == "text_delta" => {
                    self.append(value["delta"]["text"].as_str().ok_or(Error::Provider)?)?
                }
                Some("message_delta") => {
                    let output = value["usage"]["output_tokens"]
                        .as_u64()
                        .ok_or(Error::Provider)?;
                    if self.output_tokens.is_some_and(|old| output < old) {
                        return Err(Error::Provider);
                    }
                    self.output_tokens = Some(output);
                    if let Some(reason) = value["delta"]["stop_reason"].as_str() {
                        self.finished = true;
                        self.truncated = !matches!(reason, "end_turn" | "stop_sequence");
                    }
                }
                Some("message_stop") => {
                    if !self.finished {
                        return Err(Error::Provider);
                    }
                    self.set_usage(&json!({"input":self.input_tokens.ok_or(Error::Provider)?,"output":self.output_tokens.ok_or(Error::Provider)?}),"input","output")?;
                    return Ok(true);
                }
                _ => {}
            },
        }
        Ok(false)
    }
    fn finish(self) -> Result<Completion> {
        Ok(Completion {
            content: self.content,
            usage: self.usage.ok_or(Error::Invalid("provider usage missing"))?,
            truncated: self.truncated,
        })
    }
}
async fn delta(writer: &mut (impl AsyncWrite + Unpin), mut text: &str) -> Result<()> {
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
