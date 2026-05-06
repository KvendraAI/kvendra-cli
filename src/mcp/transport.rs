//! Line-delimited JSON-RPC 2.0 transport over tokio stdio.
//!
//! Each request/response is one JSON object on its own line. We use this
//! shape (over the LSP framing variant) for simplicity in Pase A — it is
//! widely supported by MCP clients in stdio mode and is trivial to test
//! manually with `jq` in shell pipelines.

use crate::error::{KvendraError, KvendraResult};
use crate::mcp::protocol::{JsonRpcRequest, JsonRpcResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};

pub struct StdioTransport {
    reader: BufReader<Stdin>,
    writer: Stdout,
}

impl StdioTransport {
    pub fn new() -> Self {
        Self {
            reader: BufReader::new(tokio::io::stdin()),
            writer: tokio::io::stdout(),
        }
    }

    /// Read one line, parse as JSON-RPC. `Ok(None)` on EOF.
    pub async fn read(&mut self) -> KvendraResult<Option<JsonRpcRequest>> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let req: JsonRpcRequest = serde_json::from_str(trimmed)
            .map_err(|e| KvendraError::McpProtocol(format!("parse: {e}")))?;
        Ok(Some(req))
    }

    pub async fn write(&mut self, resp: &JsonRpcResponse) -> KvendraResult<()> {
        let s = serde_json::to_string(resp)?;
        self.writer.write_all(s.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }
}

impl Default for StdioTransport {
    fn default() -> Self {
        Self::new()
    }
}
