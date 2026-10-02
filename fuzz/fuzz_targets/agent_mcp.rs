#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use mahi_agent::mcp::{
        self,
        Incoming,
    };
    match mcp::decode(data) {
        Incoming::Request { id, .. } => {
            let reply = mcp::reply(&id, &mcp::tool_text("ok", false));
            assert!(!reply[..reply.len() - 1].contains(&b'\n'));
        }
        Incoming::Invalid { id, error } => {
            let reply = mcp::error_reply(id.as_ref(), error);
            assert!(!reply[..reply.len() - 1].contains(&b'\n'));
        }
        Incoming::Quiet => {}
    }
});
