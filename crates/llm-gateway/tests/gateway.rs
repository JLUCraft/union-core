#[path = "../../../tests/support/mod.rs"]
mod support;
use authority::authority::Authority;
use identity::Identity;
use league::journal::Journal;
use llm_gateway::{Config, Gateway, Ledger, MemberPolicy, Provider};
use node::{AccessPolicy, Node, NodeConfig, Service, ServiceId};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};
use wire::protocol::{LLM_PROTOCOL, LlmMessage, LlmRequest, Privacy};

fn request() -> LlmRequest {
    LlmRequest {
        model: "local".into(),
        purpose: "assistant.ask".into(),
        max_tokens: 32,
        privacy: Privacy::Sensitive,
        stream: true,
        context: None,
        messages: vec![LlmMessage {
            role: "user".into(),
            content: "private prompt".into(),
        }],
    }
}
async fn provider(body: &'static str) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let header_end = loop {
                    let byte = socket.read_u8().await.unwrap();
                    bytes.push(byte);
                    if bytes.ends_with(b"\r\n\r\n") {
                        break bytes.len();
                    }
                    assert!(bytes.len() < 16384);
                };
                let header = String::from_utf8(bytes.clone()).unwrap();
                let length: usize = header
                    .lines()
                    .find_map(|s| {
                        s.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|n| n.trim().parse().unwrap())
                    })
                    .unwrap();
                bytes.resize(header_end + length, 0);
                socket.read_exact(&mut bytes[header_end..]).await.unwrap();
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[header_end..]).unwrap();
                assert_eq!(request["messages"][0]["content"], "private prompt");
                assert_eq!(request["stream_options"]["include_usage"], true);
                assert!(request.get("privacy").is_none());
                count.fetch_add(1, Ordering::SeqCst);
                if body == "slow" {
                    let mut byte = [0u8; 1];
                    // Cancellation must close the HTTP request while no output is available.
                    assert_eq!(
                        tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            socket.read(&mut byte)
                        )
                        .await
                        .unwrap()
                        .unwrap(),
                        0
                    );
                    count.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                // Deliberately split SSE JSON and UTF-8 codepoints across HTTP reads.
                for chunk in body.as_bytes().chunks(7) {
                    if socket.write_all(chunk).await.is_err() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            });
        }
    });
    (url, calls, task)
}
const SUCCESS: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"你好\"},\"finish_reason\":null}]}\r\n\r\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":2,\"total_tokens\":10}}\n\ndata: [DONE]\n\n";
const INTERRUPTED: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n";

async fn smoke(cli: Option<std::path::PathBuf>, body: &'static str) {
    let dir = tempfile::tempdir().unwrap();
    let host = Identity::generate();
    let user = Identity::generate();
    let service = ServiceId::new();
    let mut identities =
        support::Identities::new(&[(&host, "host", "jlu"), (&user, "alice", "jlu")], "host");
    identities.service(&host, &service.to_string(), "alice", "use");
    let root = identities.root("jlu");
    let view = identities
        .log
        .view(std::time::Duration::from_secs(120))
        .unwrap();
    let journal = Arc::new(Mutex::new(
        Journal::open(dir.path().join("governance"), identities.genesis()).unwrap(),
    ));
    let log = Arc::new(Mutex::new(identities.log));
    let authority = Authority::Local {
        journal,
        log: log.clone(),
        view: view.clone(),
    };
    let (url, calls, upstream) = provider(body).await;
    let (public_url, public_calls, public_upstream) = provider(SUCCESS).await;
    let model: BTreeSet<String> = ["local".into()].into();
    let config = Config {
        clubs: Default::default(),
        providers: vec![
            Provider {
                url: public_url,
                key_env: None,
                sensitive: false,
                self_hosted: true,
                models: model.clone(),
                context_tokens: 128,
            },
            Provider {
                url,
                key_env: None,
                sensitive: true,
                self_hosted: true,
                models: model.clone(),
                context_tokens: 128,
            },
        ],
        members: [(
            "alice".into(),
            MemberPolicy {
                tokens_per_day: 128,
                models: model,
            },
        )]
        .into(),
        purposes: ["assistant.ask".into()].into(),
        templates: Default::default(),
        max_tokens: 32,
        max_messages: 8,
        max_input_bytes: 1024,
        concurrency: 2,
    };
    let ledger_path = dir.path().join("usage");
    let gateway =
        Arc::new(Gateway::new(config, Ledger::open(&ledger_path).unwrap(), authority).unwrap());
    let mut server = Node::start(host.clone(), NodeConfig::default())
        .await
        .unwrap();
    server
        .publish(Service {
            metadata: Vec::new(),
            id: service,
            name: "llm".into(),
            protocol: LLM_PROTOCOL.into(),
            access: AccessPolicy::Trust {
                view: view.clone(),
                requirement: wire::protocol::TrustRequirement {
                    clubs: Default::default(),
                    permission: Some("use".into()),
                },
            },
        })
        .await
        .unwrap();
    let mut incoming = server.take_incoming().unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(session) = incoming.recv() => {
                    let gateway = gateway.clone();
                    tasks.spawn(async move { gateway.serve(session).await });
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    let client = Node::start(user.clone(), NodeConfig::default())
        .await
        .unwrap();
    client.dial(server.addresses()[0].clone()).await.unwrap();
    if body == "slow" {
        let ask = client::llm::ask(&client, host.peer_id(), service, request(), |_| {});
        let revoke = async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            let mut log = log.lock().await;
            let mut record = log
                .state()
                .draft(wire::protocol::TrustAction::RevokePermission {
                    id: format!("{service}-alice"),
                });
            identity::trust::sign(&mut record, &root).unwrap();
            log.append(record).unwrap();
            log.mark_current().unwrap();
        };
        let (answer, ()) = tokio::join!(ask, revoke);
        assert!(answer.unwrap().error.is_some());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(client.open_service(host.peer_id(), service).await.is_err());
    } else if let Some(binary) = cli {
        let key = dir.path().join("device");
        user.save_new(&key).unwrap();
        let address = server.addresses()[0].to_string();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(binary)
                .args(["llm", "ask", "--key"])
                .arg(key)
                .args([
                    "--address",
                    &address,
                    "--peer",
                    &host.peer_id().to_string(),
                    "--service",
                    &service.to_string(),
                ])
                .args([
                    "--model",
                    "local",
                    "--max-tokens",
                    "32",
                    "--sensitive",
                    "private prompt",
                ])
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("你好"));
    } else {
        let answer = client::llm::ask(&client, host.peer_id(), service, request(), |_| {})
            .await
            .unwrap();
        if body == SUCCESS {
            assert_eq!(answer.content, "你好");
            assert_eq!(answer.usage.unwrap().total_tokens, 10);
            assert!(!answer.truncated);
            assert!(answer.error.is_none());
        } else {
            assert_eq!(answer.content, "partial");
            assert!(answer.truncated);
            assert!(answer.error.is_some());
        }
        // Even after settlement only 118 tokens remain, below the next reservation.
        let denied = client::llm::ask(&client, host.peer_id(), service, request(), |_| {})
            .await
            .unwrap();
        assert!(denied.error.unwrap().contains("quota"));
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        if body == "slow" { 2 } else { 1 }
    );
    assert_eq!(public_calls.load(Ordering::SeqCst), 0);
    let ledger = std::fs::read_to_string(ledger_path).unwrap();
    assert!(!ledger.contains("private prompt"));
    assert!(!ledger.contains("你好"));
    task.abort();
    upstream.abort();
    public_upstream.abort();
    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}
#[tokio::test]
async fn identity_sensitive_routing_usage_and_quota() {
    tokio::time::timeout(std::time::Duration::from_secs(20), smoke(None, SUCCESS))
        .await
        .unwrap();
}
#[tokio::test]
async fn interrupted_stream_preserves_output_and_reservation() {
    tokio::time::timeout(std::time::Duration::from_secs(20), smoke(None, INTERRUPTED))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "build unionctl, then set UNIONCTL_BIN to its absolute executable path"]
async fn unionctl_ask_smoke() {
    let binary = std::env::var_os("UNIONCTL_BIN")
        .expect("UNIONCTL_BIN required")
        .into();
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        smoke(Some(binary), SUCCESS),
    )
    .await
    .unwrap();
}
#[test]
fn ledger_restart_tamper_lock_and_sliding_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    let mut ledger = Ledger::open(&path).unwrap();
    assert!(Ledger::open(&path).is_err());
    let id = ledger
        .reserve(
            llm_gateway::Reservation {
                member: "alice",
                club: "jlu",
                model: "local",
                purpose: "assistant.ask",
                tokens: 100,
            },
            llm_gateway::Quotas {
                member: Some(100),
                club: None,
            },
            1000,
        )
        .unwrap();
    assert!(
        ledger
            .reserve(
                llm_gateway::Reservation {
                    member: "alice",
                    club: "jlu",
                    model: "local",
                    purpose: "assistant.ask",
                    tokens: 1
                },
                llm_gateway::Quotas {
                    member: Some(100),
                    club: None
                },
                1001
            )
            .is_err()
    );
    ledger.settle(id, 40, 1002).unwrap();
    drop(ledger);
    let mut ledger = Ledger::open(&path).unwrap();
    assert!(
        ledger
            .reserve(
                llm_gateway::Reservation {
                    member: "alice",
                    club: "jlu",
                    model: "local",
                    purpose: "assistant.ask",
                    tokens: 61
                },
                llm_gateway::Quotas {
                    member: Some(100),
                    club: None
                },
                1003
            )
            .is_err()
    );
    assert!(
        ledger
            .reserve(
                llm_gateway::Reservation {
                    member: "alice",
                    club: "jlu",
                    model: "local",
                    purpose: "assistant.ask",
                    tokens: 60
                },
                llm_gateway::Quotas {
                    member: Some(100),
                    club: None
                },
                999
            )
            .is_err()
    );
    ledger
        .reserve(
            llm_gateway::Reservation {
                member: "alice",
                club: "jlu",
                model: "local",
                purpose: "assistant.ask",
                tokens: 60,
            },
            llm_gateway::Quotas {
                member: Some(100),
                club: None,
            },
            1003,
        )
        .unwrap();
    assert!(
        ledger
            .reserve(
                llm_gateway::Reservation {
                    member: "alice",
                    club: "jlu",
                    model: "local",
                    purpose: "assistant.ask",
                    tokens: 41
                },
                llm_gateway::Quotas {
                    member: Some(100),
                    club: None
                },
                86_401_000
            )
            .is_err()
    );
    ledger
        .reserve(
            llm_gateway::Reservation {
                member: "alice",
                club: "jlu",
                model: "local",
                purpose: "assistant.ask",
                tokens: 100,
            },
            llm_gateway::Quotas {
                member: Some(100),
                club: None,
            },
            86_401_003,
        )
        .unwrap();
    drop(ledger);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value[0]["time_ms"] = 999.into();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(Ledger::open(path).is_err());
}

#[tokio::test]
async fn revocation_cancels_waiting_provider() {
    tokio::time::timeout(std::time::Duration::from_secs(15), smoke(None, "slow"))
        .await
        .unwrap();
}

// Fictional fixture only — real prompt templates live exclusively in the
// operator's deployment config outside the repository.
const EVENTS_TEMPLATE: &str = "fixture template prefix with instructions\n{context}";

async fn capturing_provider(
    body: &'static str,
) -> (
    String,
    Arc<Mutex<Vec<serde_json::Value>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let captured = bodies.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let captured = captured.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let header_end = loop {
                    let byte = socket.read_u8().await.unwrap();
                    bytes.push(byte);
                    if bytes.ends_with(b"\r\n\r\n") {
                        break bytes.len();
                    }
                    assert!(bytes.len() < 16384);
                };
                let header = String::from_utf8(bytes.clone()).unwrap();
                let length: usize = header
                    .lines()
                    .find_map(|s| {
                        s.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|n| n.trim().parse().unwrap())
                    })
                    .unwrap();
                bytes.resize(header_end + length, 0);
                socket.read_exact(&mut bytes[header_end..]).await.unwrap();
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[header_end..]).unwrap();
                captured.lock().await.push(request);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(body.as_bytes()).await.unwrap();
            });
        }
    });
    (url, bodies, task)
}

#[tokio::test]
async fn templated_purpose_composes_prompt_and_rejects_smuggled_input() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let dir = tempfile::tempdir().unwrap();
        let host = Identity::generate();
        let user = Identity::generate();
        let service = ServiceId::new();
        let mut identities =
            support::Identities::new(&[(&host, "host", "jlu"), (&user, "alice", "jlu")], "host");
        identities.service(&host, &service.to_string(), "alice", "use");
        let view = identities
            .log
            .view(std::time::Duration::from_secs(120))
            .unwrap();
        let journal = Arc::new(Mutex::new(
            Journal::open(dir.path().join("governance"), identities.genesis()).unwrap(),
        ));
        let log = Arc::new(Mutex::new(identities.log));
        let authority = Authority::Local {
            journal,
            log: log.clone(),
            view: view.clone(),
        };
        let (url, bodies, upstream) = capturing_provider(SUCCESS).await;
        let model: BTreeSet<String> = ["local".into()].into();
        let config = Config {
            clubs: Default::default(),
            providers: vec![Provider {
                url,
                key_env: None,
                sensitive: false,
                self_hosted: true,
                models: model.clone(),
                context_tokens: 128,
            }],
            members: [(
                "alice".into(),
                MemberPolicy {
                    tokens_per_day: 1_000_000,
                    models: model,
                },
            )]
            .into(),
            purposes: ["assistant.ask".into(), "events.draft".into()].into(),
            templates: [("events.draft".into(), EVENTS_TEMPLATE.into())].into(),
            max_tokens: 32,
            max_messages: 8,
            max_input_bytes: 1024,
            concurrency: 2,
        };
        let gateway = Arc::new(
            Gateway::new(
                config,
                Ledger::open(dir.path().join("usage")).unwrap(),
                authority,
            )
            .unwrap(),
        );
        let mut server = Node::start(host.clone(), NodeConfig::default())
            .await
            .unwrap();
        server
            .publish(Service {
                metadata: Vec::new(),
                id: service,
                name: "llm".into(),
                protocol: LLM_PROTOCOL.into(),
                access: AccessPolicy::Trust {
                    view: view.clone(),
                    requirement: wire::protocol::TrustRequirement {
                        clubs: Default::default(),
                        permission: Some("use".into()),
                    },
                },
            })
            .await
            .unwrap();
        let mut incoming = server.take_incoming().unwrap();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(session) = incoming.recv() => {
                        let gateway = gateway.clone();
                        tasks.spawn(async move { gateway.serve(session).await });
                    },
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        let client = Node::start(user.clone(), NodeConfig::default())
            .await
            .unwrap();
        client.dial(server.addresses()[0].clone()).await.unwrap();
        // Templated purpose: the gateway composes the user message from the
        // configured template and the client-supplied facts.
        let mut templated = request();
        templated.purpose = "events.draft".into();
        templated.privacy = Privacy::Public;
        templated.messages = Vec::new();
        templated.context = Some("活动：X\n时间窗口：Y".into());
        let answer = client::llm::ask(&client, host.peer_id(), service, templated, |_| {})
            .await
            .unwrap();
        assert_eq!(answer.content, "你好");
        assert!(answer.error.is_none());
        {
            let bodies = bodies.lock().await;
            assert_eq!(bodies.len(), 1);
            let messages = bodies[0]["messages"].as_array().unwrap();
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0]["role"], "user");
            assert_eq!(
                messages[0]["content"],
                EVENTS_TEMPLATE.replace("{context}", "活动：X\n时间窗口：Y")
            );
        }
        // Non-empty messages alongside a templated purpose are rejected.
        let mut smuggled = request();
        smuggled.purpose = "events.draft".into();
        smuggled.privacy = Privacy::Public;
        smuggled.context = Some("活动：X".into());
        let answer = client::llm::ask(&client, host.peer_id(), service, smuggled, |_| {})
            .await
            .unwrap();
        assert!(answer.error.is_some());
        // Missing context is rejected.
        let mut missing = request();
        missing.purpose = "events.draft".into();
        missing.privacy = Privacy::Public;
        missing.messages = Vec::new();
        let answer = client::llm::ask(&client, host.peer_id(), service, missing, |_| {})
            .await
            .unwrap();
        assert!(answer.error.is_some());
        // Empty context is rejected.
        let mut empty = request();
        empty.purpose = "events.draft".into();
        empty.privacy = Privacy::Public;
        empty.messages = Vec::new();
        empty.context = Some(String::new());
        let answer = client::llm::ask(&client, host.peer_id(), service, empty, |_| {})
            .await
            .unwrap();
        assert!(answer.error.is_some());
        // Context on a purpose without a template is rejected.
        let mut untemplated = request();
        untemplated.privacy = Privacy::Public;
        untemplated.context = Some("活动：X".into());
        let answer = client::llm::ask(&client, host.peer_id(), service, untemplated, |_| {})
            .await
            .unwrap();
        assert!(answer.error.is_some());
        // None of the rejected requests reached the upstream provider.
        assert_eq!(bodies.lock().await.len(), 1);
        let ledger = std::fs::read_to_string(dir.path().join("usage")).unwrap();
        assert!(!ledger.contains("活动：X"));
        assert!(!ledger.contains("你好"));
        task.abort();
        upstream.abort();
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn gateway_rejects_unreachable_and_invalid_templates() {
    fn build(
        templates: BTreeMap<String, String>,
    ) -> Result<Gateway<league::LeagueDomain>, llm_gateway::Error> {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let identities = support::Identities::new(&[(&identity, "admin", "jlu")], "admin");
        let view = identities
            .log
            .view(std::time::Duration::from_secs(60))
            .unwrap();
        let journal = Journal::open(dir.path().join("journal"), identities.genesis()).unwrap();
        let config = Config {
            clubs: Default::default(),
            providers: vec![Provider {
                url: "http://127.0.0.1:1/v1/chat/completions".into(),
                key_env: None,
                sensitive: false,
                self_hosted: true,
                models: ["local".into()].into(),
                context_tokens: 128,
            }],
            members: [(
                "alice".into(),
                MemberPolicy {
                    tokens_per_day: 1024,
                    models: ["local".into()].into(),
                },
            )]
            .into(),
            purposes: ["events.draft".into()].into(),
            templates,
            max_tokens: 32,
            max_messages: 8,
            max_input_bytes: 1024,
            concurrency: 1,
        };
        Gateway::new(
            config,
            Ledger::open(dir.path().join("usage")).unwrap(),
            Authority::Local {
                journal: Arc::new(Mutex::new(journal)),
                log: Arc::new(Mutex::new(identities.log)),
                view,
            },
        )
    }
    // Template key outside the purposes whitelist is unreachable configuration.
    let mut unreachable = BTreeMap::new();
    unreachable.insert("not.whitelisted".into(), "指令\n{context}".into());
    assert!(build(unreachable).is_err());
    // A template without exactly one `{context}` placeholder is invalid.
    let mut no_placeholder = BTreeMap::new();
    no_placeholder.insert("events.draft".into(), "没有任何占位符".into());
    assert!(build(no_placeholder).is_err());
    let mut blank = BTreeMap::new();
    blank.insert("events.draft".into(), "   \n  ".into());
    assert!(build(blank).is_err());
    let mut valid = BTreeMap::new();
    valid.insert("events.draft".into(), EVENTS_TEMPLATE.into());
    assert!(build(valid).is_ok());
}
