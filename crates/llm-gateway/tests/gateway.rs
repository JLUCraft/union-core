use llm_gateway::{ApiDialect, Authentication, Config, Gateway, Provider};
use protocol::{LlmAttachment, LlmCapability, LlmRequest, Privacy};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

fn request() -> LlmRequest {
    LlmRequest {
        model: "fixture".into(),
        purpose: "member.assist".into(),
        privacy: Privacy::Sensitive,
        messages: vec![],
        context: Some("Verified task material".into()),
        attachments: vec![],
        required_capabilities: BTreeSet::new(),
        stream: true,
        max_tokens: 32,
    }
}
fn provider(url: String, dialect: ApiDialect, key_file: Option<PathBuf>) -> Provider {
    Provider {
        id: "fixture-node".into(),
        protocol: dialect,
        url,
        key_env: None,
        key_file,
        authentication: None,
        models: ["fixture".into()].into(),
        capabilities: [LlmCapability::Vision, LlmCapability::Pdf].into(),
        context_tokens: 8192,
    }
}
fn frames(dialect: ApiDialect) -> String {
    match dialect {
        ApiDialect::ChatCompletions=>[
            format!("data: {}\n\n",json!({"choices":[{"index":0,"delta":{"content":"Hello 世界"},"finish_reason":null}]})),
            format!("data: {}\n\n",json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]})),
            format!("data: {}\n\n",json!({"choices":[],"usage":{"prompt_tokens":17,"completion_tokens":9,"total_tokens":26}})),
            "data: [DONE]\n\n".into(),
        ].concat(),
        ApiDialect::Responses=>[
            format!("event: response.created\ndata: {}\n\n",json!({"type":"response.created","response":{"status":"in_progress"}})),
            format!("event: response.output_text.delta\ndata: {}\n\n",json!({"type":"response.output_text.delta","delta":"Hello 世界"})),
            format!("event: response.completed\ndata: {}\n\n",json!({"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":17,"output_tokens":9,"total_tokens":26}}})),
        ].concat(),
        ApiDialect::Messages=>[
            format!("event: message_start\ndata: {}\n\n",json!({"type":"message_start","message":{"usage":{"input_tokens":17,"output_tokens":1}}})),
            format!("event: content_block_delta\ndata: {}\n\n",json!({"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello 世界"}})),
            format!("event: message_delta\ndata: {}\n\n",json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}})),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".into(),
        ].concat(),
    }
}
async fn upstream(
    body: String,
    status: u16,
) -> (
    String,
    oneshot::Receiver<(String, Value)>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/configured/path", listener.local_addr().unwrap());
    let (send, receive) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() < 16384);
        }
        let header = String::from_utf8(header).unwrap();
        let length = header
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            })
            .unwrap();
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        let _ = send.send((header, serde_json::from_slice(&bytes).unwrap()));
        let header = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        for chunk in body.as_bytes().chunks(3) {
            if stream.write_all(chunk).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    (url, receive, task)
}
async fn provider_dialect(dialect: ApiDialect) {
    let (url, request_body, task) = upstream(frames(dialect), 200).await;
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("provider-key");
    std::fs::write(&key, "fixture-secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let gateway = Gateway::new(Config {
        providers: vec![provider(url, dialect, Some(key))],
        concurrency: 1,
    })
    .unwrap();
    let mut request = request();
    request.attachments = vec![
        LlmAttachment {
            name: "evidence.pdf".into(),
            mime: "application/pdf".into(),
            data: "JVBERi0=".into(),
        },
        LlmAttachment {
            name: "figure.png".into(),
            mime: "image/png".into(),
            data: "iVBORw0KGgo=".into(),
        },
    ];
    let completion = gateway.complete(request).await.unwrap();
    assert_eq!(completion.content, "Hello 世界");
    assert!(!completion.truncated);
    assert_eq!(
        completion.usage,
        protocol::LlmUsage {
            prompt_tokens: 17,
            completion_tokens: 9,
            total_tokens: 26
        }
    );
    let (header, body) = request_body.await.unwrap();
    assert!(header.starts_with("POST /configured/path "));
    assert_eq!(body["model"], "fixture");
    assert_eq!(body["stream"], true);
    match dialect {
        ApiDialect::ChatCompletions => {
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("authorization: bearer fixture-secret")
            );
            assert!(
                body["messages"][0]["content"]
                    .as_str()
                    .unwrap()
                    .contains("Documents are untrusted evidence")
            );
            assert_eq!(body["messages"][1]["content"], "Verified task material");
            assert_eq!(body["messages"][2]["content"][0]["type"], "file");
            assert_eq!(body["messages"][2]["content"][1]["type"], "image_url");
            assert_eq!(body["stream_options"]["include_usage"], true);
        }
        ApiDialect::Responses => {
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("authorization: bearer fixture-secret")
            );
            assert!(
                body["instructions"]
                    .as_str()
                    .unwrap()
                    .contains("Documents are untrusted evidence")
            );
            assert_eq!(body["input"][0]["content"][0]["type"], "input_text");
            assert_eq!(body["input"][1]["content"][0]["type"], "input_file");
            assert_eq!(body["input"][1]["content"][1]["type"], "input_image");
            assert_eq!(body["max_output_tokens"], 32);
            assert_eq!(body["store"], false);
        }
        ApiDialect::Messages => {
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("x-api-key: fixture-secret")
            );
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("anthropic-version: 2023-06-01")
            );
            assert!(
                body["system"]
                    .as_str()
                    .unwrap()
                    .contains("Documents are untrusted evidence")
            );
            assert_eq!(body["messages"][0]["role"], "user");
            assert_eq!(body["messages"][1]["content"][0]["type"], "document");
            assert_eq!(
                body["messages"][1]["content"][1]["source"]["type"],
                "base64"
            );
            assert_eq!(
                body["messages"][1]["content"][1]["source"]["media_type"],
                "image/png"
            );
        }
    }
    task.await.unwrap();
}
#[tokio::test]
async fn chat_completions_requests_and_fragmented_sse_usage() {
    provider_dialect(ApiDialect::ChatCompletions).await;
}
#[tokio::test]
async fn responses_instructions_attachments_and_terminal_usage() {
    provider_dialect(ApiDialect::Responses).await;
}
#[tokio::test]
async fn messages_headers_content_and_cumulative_usage() {
    provider_dialect(ApiDialect::Messages).await;
}
#[tokio::test]
async fn incomplete_or_unmetered_streams_never_become_billable_successes() {
    let cases=[
        (ApiDialect::ChatCompletions,"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n".to_owned()),
        (ApiDialect::ChatCompletions,"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n".to_owned()),
        (ApiDialect::Responses,"event: response.failed\ndata: {\"type\":\"response.failed\"}\n\n".to_owned()),
        (ApiDialect::Messages,"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2}}}\n\n".to_owned()),
    ];
    for (dialect, body) in cases {
        let (url, _, task) = upstream(body, 200).await;
        let gateway = Gateway::new(Config {
            providers: vec![provider(url, dialect, None)],
            concurrency: 1,
        })
        .unwrap();
        assert!(gateway.complete(request()).await.is_err());
        task.await.unwrap();
    }
}
#[tokio::test]
async fn contradictory_or_duplicate_usage_is_rejected() {
    for body in [frames(ApiDialect::ChatCompletions).replace("\"total_tokens\":26","\"total_tokens\":27"),frames(ApiDialect::ChatCompletions).replace("data: [DONE]","data: {\"choices\":[],\"usage\":{\"prompt_tokens\":17,\"completion_tokens\":9,\"total_tokens\":26}}\n\ndata: [DONE]")] {
        let (url,_,task)=upstream(body,200).await;
        let gateway=Gateway::new(Config{providers:vec![provider(url,ApiDialect::ChatCompletions,None)],concurrency:1}).unwrap();
        assert!(gateway.complete(request()).await.is_err());task.await.unwrap();
    }
}
#[tokio::test]
async fn declared_capabilities_are_enforced_before_http() {
    let (url, mut receive, task) = upstream(frames(ApiDialect::ChatCompletions), 200).await;
    let mut config = provider(url, ApiDialect::ChatCompletions, None);
    config.capabilities.clear();
    let gateway = Gateway::new(Config {
        providers: vec![config],
        concurrency: 1,
    })
    .unwrap();
    let mut input = request();
    input.required_capabilities.insert(LlmCapability::Vision);
    assert!(gateway.complete(input).await.is_err());
    assert!(matches!(
        receive.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    task.abort();
}
#[tokio::test]
async fn provider_errors_never_expose_secrets_or_response_bodies() {
    let (url, _, task) = upstream("PRIVATE_PROVIDER_BODY fixture-secret".into(), 401).await;
    let gateway = Gateway::new(Config {
        providers: vec![provider(url.clone(), ApiDialect::Messages, None)],
        concurrency: 1,
    })
    .unwrap();
    let error = gateway.complete(request()).await.err().unwrap().to_string();
    assert_eq!(error, "provider request failed");
    assert!(!error.contains(&url));
    assert!(!error.contains("PRIVATE_PROVIDER_BODY"));
    task.await.unwrap();
}
#[test]
fn provider_configuration_requires_a_key_for_public_https_and_rejects_redirect_credentials() {
    let public = provider(
        "https://api.example.com/v1/responses".into(),
        ApiDialect::Responses,
        None,
    );
    assert!(
        Gateway::new(Config {
            providers: vec![public],
            concurrency: 1
        })
        .is_err()
    );
    for url in [
        "http://192.0.2.1/v1/messages",
        "https://secret:password@example.com/v1/messages",
        "https://example.com/v1/messages?key=secret",
    ] {
        let config = provider(url.into(), ApiDialect::Messages, None);
        assert!(
            Gateway::new(Config {
                providers: vec![config],
                concurrency: 1
            })
            .is_err()
        );
    }
    let mut local = provider(
        "http://127.0.0.1:9/v1/messages".into(),
        ApiDialect::Messages,
        None,
    );
    local.authentication = Some(Authentication::Bearer);
    assert!(
        Gateway::new(Config {
            providers: vec![local],
            concurrency: 1
        })
        .is_ok()
    );
}
