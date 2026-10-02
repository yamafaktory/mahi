//! The Model Context Protocol as mahi serves it to an agent: JSON-RPC 2.0 messages, one per
//! line, the calls mahi answers, and the replies it writes.

use serde::Serialize;
use serde_json::{
    Map,
    Value,
    json,
};

/// The longest message mahi reads from an agent, in bytes, newline included.
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;
/// The protocol versions mahi speaks, newest first; 2025-03-26, which requires JSON-RPC
/// batches, is not one of them.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-11-25", "2025-06-18", "2024-11-05"];
const MAX_ID_CHARS: usize = 256;
const MAX_NAME_BYTES: usize = 128;

/// The id of a request, which its reply carries back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum RequestId {
    /// A numeric id.
    Number(i64),
    /// A text id, of at most 256 characters.
    Text(String),
}

impl RequestId {
    fn from_value(value: Value) -> Option<Self> {
        match value {
            Value::Number(number) => number.as_i64().map(Self::Number),
            Value::String(text) if text.chars().count() <= MAX_ID_CHARS => Some(Self::Text(text)),
            _ => None,
        }
    }
}

/// What an agent asked for.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    /// Starts the session, in the protocol version the agent prefers.
    Initialize {
        /// The version the agent asked for.
        protocol_version: String,
    },
    /// Asks whether mahi still answers.
    Ping,
    /// Asks which tools mahi offers.
    ListTools,
    /// Runs the tool `name` with `arguments`.
    CallTool {
        /// The tool's name.
        name: String,
        /// Its arguments, by name.
        arguments: Map<String, Value>,
    },
    /// A method mahi does not serve.
    Unknown,
}

/// A JSON-RPC error mahi replies with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    /// The message is not JSON.
    Parse,
    /// The message is not a JSON-RPC 2.0 request.
    InvalidRequest,
    /// The method is not one mahi serves.
    MethodNotFound,
    /// The parameters do not fit the method.
    InvalidParams,
}

impl RpcError {
    fn code(self) -> i64 {
        match self {
            Self::Parse => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Parse => "parse error",
            Self::InvalidRequest => "invalid request",
            Self::MethodNotFound => "method not found",
            Self::InvalidParams => "invalid params",
        }
    }
}

/// One message from the agent, decoded.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// A request, to be answered under `id`.
    Request {
        /// The request's id.
        id: RequestId,
        /// What it asks for.
        call: Call,
    },
    /// A notification or a reply, which mahi does not answer.
    Quiet,
    /// A message that cannot be served, answered with `error` under `id` when it has one.
    Invalid {
        /// The request's id, when it could be read.
        id: Option<RequestId>,
        /// Why it cannot be served.
        error: RpcError,
    },
}

/// Decodes one message, a line without its newline.
#[must_use]
pub fn decode(line: &[u8]) -> Incoming {
    let invalid = |id, error| Incoming::Invalid { id, error };
    if line.len() >= MAX_MESSAGE_BYTES {
        return invalid(None, RpcError::InvalidRequest);
    }
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        return invalid(None, RpcError::Parse);
    };
    let Value::Object(mut message) = message else {
        return invalid(None, RpcError::InvalidRequest);
    };
    let id = message.remove("id").map(RequestId::from_value);
    let Some(Value::String(method)) = message.remove("method") else {
        return match id {
            Some(_) if message.contains_key("result") || message.contains_key("error") => {
                Incoming::Quiet
            }
            Some(id) => invalid(id, RpcError::InvalidRequest),
            None => invalid(None, RpcError::InvalidRequest),
        };
    };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid(id.flatten(), RpcError::InvalidRequest);
    }
    let id = match id {
        None => return Incoming::Quiet,
        Some(None) => return invalid(None, RpcError::InvalidRequest),
        Some(Some(id)) => id,
    };
    let params = match message.remove("params") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(params)) => params,
        Some(_) => return invalid(Some(id), RpcError::InvalidParams),
    };
    match call(&method, params) {
        Ok(call) => Incoming::Request { id, call },
        Err(error) => invalid(Some(id), error),
    }
}

fn bounded_text(value: Option<Value>) -> Result<String, RpcError> {
    match value {
        Some(Value::String(text)) if text.len() <= MAX_NAME_BYTES => Ok(text),
        _ => Err(RpcError::InvalidParams),
    }
}

fn call(method: &str, mut params: Map<String, Value>) -> Result<Call, RpcError> {
    Ok(match method {
        "initialize" => Call::Initialize {
            protocol_version: bounded_text(params.remove("protocolVersion"))?,
        },
        "ping" => Call::Ping,
        "tools/list" => Call::ListTools,
        "tools/call" => {
            let name = bounded_text(params.remove("name"))?;
            let arguments = match params.remove("arguments") {
                None | Some(Value::Null) => Map::new(),
                Some(Value::Object(arguments)) => arguments,
                Some(_) => return Err(RpcError::InvalidParams),
            };
            Call::CallTool { name, arguments }
        }
        _ => Call::Unknown,
    })
}

/// Returns the version mahi answers an agent that asked for `requested` with: that one when
/// mahi speaks it, or else the newest it speaks.
#[must_use]
pub fn agreed_version(requested: &str) -> &'static str {
    PROTOCOL_VERSIONS
        .iter()
        .find(|version| **version == requested)
        .copied()
        .unwrap_or(PROTOCOL_VERSIONS[0])
}

/// A tool mahi offers: its name, what it does, and the JSON schema of its arguments.
#[derive(Debug, Clone)]
pub struct Tool {
    /// The tool's name.
    pub name: &'static str,
    /// What the tool does, for the agent.
    pub description: &'static str,
    /// The JSON schema of its arguments.
    pub input_schema: Value,
}

/// Returns the reply to `initialize` for a server called `name` at `version`, in the protocol
/// version agreed for `requested`, with `instructions` for the agent.
#[must_use]
pub fn initialized(requested: &str, (name, version): (&str, &str), instructions: &str) -> Value {
    json!({
        "protocolVersion": agreed_version(requested),
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": name, "version": version },
        "instructions": instructions,
    })
}

/// Returns the reply to `tools/list` offering `tools`.
#[must_use]
pub fn tool_list(tools: &[Tool]) -> Value {
    let tools: Vec<Value> = tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            })
        })
        .collect();
    json!({ "tools": tools })
}

/// Returns the reply to `tools/call` holding `text`, marked as an error of the tool when
/// `failed`.
#[must_use]
pub fn tool_text(text: &str, failed: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": failed,
    })
}

/// Writes the reply carrying `result` to the request `id`, as one line.
#[must_use]
pub fn reply(id: &RequestId, result: &Value) -> Vec<u8> {
    line(&Envelope {
        jsonrpc: "2.0",
        id: Some(id),
        result: Some(result),
        error: None,
    })
}

/// Writes the error reply `error` to the request `id`, or to an unknown request, as one line.
#[must_use]
pub fn error_reply(id: Option<&RequestId>, error: RpcError) -> Vec<u8> {
    line(&Envelope {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(ErrorBody {
            code: error.code(),
            message: error.message(),
        }),
    })
}

#[derive(Serialize)]
struct Envelope<'a> {
    jsonrpc: &'static str,
    id: Option<&'a RequestId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: i64,
    message: &'static str,
}

fn line(message: &Envelope<'_>) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(message).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// Reads the text argument `name` of a tool call, of at most `most` characters: `None` when
/// it is absent, and an error when it is not text or too long.
///
/// # Errors
///
/// Returns [`RpcError::InvalidParams`] if the argument is not text or is too long.
pub fn text_argument<'a>(
    arguments: &'a Map<String, Value>,
    name: &str,
    most: usize,
) -> Result<Option<&'a str>, RpcError> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.chars().count() <= most => Ok(Some(text)),
        Some(_) => Err(RpcError::InvalidParams),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(text: &str) -> Incoming {
        decode(text.as_bytes())
    }

    #[test]
    fn requests_are_decoded_into_the_calls_mahi_serves() {
        assert_eq!(
            decoded(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#
            ),
            Incoming::Request {
                id: RequestId::Number(1),
                call: Call::Initialize {
                    protocol_version: "2025-06-18".to_owned()
                }
            }
        );
        assert_eq!(
            decoded(r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#),
            Incoming::Request {
                id: RequestId::Text("a".to_owned()),
                call: Call::ListTools
            }
        );
        let Incoming::Request {
            call: Call::CallTool { name, arguments },
            ..
        } = decoded(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_diff","arguments":{"agent":"bob.codex"}}}"#,
        )
        else {
            panic!("not a tool call");
        };
        assert_eq!(name, "read_diff");
        assert_eq!(
            text_argument(&arguments, "agent", 64),
            Ok(Some("bob.codex"))
        );
        assert_eq!(text_argument(&arguments, "path", 64), Ok(None));
        assert_eq!(
            text_argument(&arguments, "agent", 3),
            Err(RpcError::InvalidParams)
        );
        assert_eq!(
            decoded(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#),
            Incoming::Request {
                id: RequestId::Number(3),
                call: Call::Ping
            }
        );
        assert_eq!(
            decoded(r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#),
            Incoming::Request {
                id: RequestId::Number(4),
                call: Call::Unknown
            }
        );
    }

    #[test]
    fn notifications_and_replies_are_not_answered_and_bad_messages_are() {
        assert_eq!(
            decoded(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Incoming::Quiet
        );
        assert_eq!(
            decoded(r#"{"jsonrpc":"2.0","id":9,"result":{}}"#),
            Incoming::Quiet
        );
        let cases = [
            ("not json", None, RpcError::Parse),
            ("[1,2]", None, RpcError::InvalidRequest),
            ("5", None, RpcError::InvalidRequest),
            (
                r#"{"id":1,"method":"ping"}"#,
                Some(RequestId::Number(1)),
                RpcError::InvalidRequest,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
                None,
                RpcError::InvalidRequest,
            ),
            (
                r#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#,
                None,
                RpcError::InvalidRequest,
            ),
            (
                r#"{"jsonrpc":"2.0","id":7}"#,
                Some(RequestId::Number(7)),
                RpcError::InvalidRequest,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}"#,
                Some(RequestId::Number(1)),
                RpcError::InvalidParams,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                Some(RequestId::Number(1)),
                RpcError::InvalidParams,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":[]}}"#,
                Some(RequestId::Number(1)),
                RpcError::InvalidParams,
            ),
        ];
        for (text, id, error) in cases {
            assert_eq!(decoded(text), Incoming::Invalid { id, error }, "{text}");
        }
        let long_id = format!(
            r#"{{"jsonrpc":"2.0","id":"{}","method":"ping"}}"#,
            "x".repeat(257)
        );
        assert_eq!(
            decoded(&long_id),
            Incoming::Invalid {
                id: None,
                error: RpcError::InvalidRequest
            }
        );
        let huge = vec![b' '; MAX_MESSAGE_BYTES];
        assert_eq!(
            decode(&huge),
            Incoming::Invalid {
                id: None,
                error: RpcError::InvalidRequest
            }
        );
    }

    #[test]
    fn replies_are_single_json_lines_carrying_the_request_id() {
        let id = RequestId::Text("x\ny".to_owned());
        let reply = reply(&id, &tool_text("line one\nline two", false));
        assert!(!reply[..reply.len() - 1].contains(&b'\n'));
        assert!(reply.ends_with(b"\n"));
        let value: Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(value["id"], "x\ny");
        assert_eq!(value["result"]["content"][0]["text"], "line one\nline two");
        assert_eq!(value["result"]["isError"], false);
        let error: Value = serde_json::from_slice(&error_reply(None, RpcError::Parse)).unwrap();
        assert_eq!(error["id"], Value::Null);
        assert_eq!(error["error"]["code"], -32700);
    }

    #[test]
    fn the_agreed_version_is_the_asked_one_when_spoken_or_else_the_newest() {
        assert_eq!(agreed_version("2024-11-05"), "2024-11-05");
        assert_eq!(agreed_version("2025-03-26"), PROTOCOL_VERSIONS[0]);
        assert_eq!(agreed_version("1999-01-01"), PROTOCOL_VERSIONS[0]);
        let started = initialized("2025-06-18", ("mahi", "0.1.0"), "use the tools");
        assert_eq!(started["protocolVersion"], "2025-06-18");
        assert_eq!(started["serverInfo"]["name"], "mahi");
        let listed = tool_list(&[Tool {
            name: "list_agents",
            description: "lists",
            input_schema: json!({ "type": "object", "properties": {} }),
        }]);
        assert_eq!(listed["tools"][0]["inputSchema"]["type"], "object");
    }
}
