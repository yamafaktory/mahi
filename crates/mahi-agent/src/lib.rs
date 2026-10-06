//! How mahi speaks with the agents it wraps: the messages their hooks send, what it reads of
//! each agent's own files and payloads, and the profiles users write for their agents.

pub mod claude_code;
pub mod hook;
pub mod mcp;
pub mod payload;
pub mod profile;
