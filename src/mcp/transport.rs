//! Line-delimited JSON-RPC 2.0 transport over tokio stdio.
//!
//! Each request/response is one JSON object on its own line. We use this
//! shape (over the LSP framing variant) for simplicity in Pase A — it is
//! widely supported by MCP clients in stdio mode and is trivial to test
//! manually with `jq` in shell pipelines.

use crate::error::{KvendraError, KvendraResult};
use crate::mcp::protocol::{JsonRpcRequest, JsonRpcResponse};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};

/// Read one JSON-RPC request line from any line-buffered async reader.
///
/// `Ok(None)` is returned **only** on a real EOF (`read_line` yields
/// `n == 0`). A non-empty read whose content is blank/whitespace is a
/// spurious line (e.g. a stray newline injected by a misbehaving child that
/// briefly touched the inherited stdin pipe): we skip it and keep reading
/// instead of treating it as EOF, which would silently terminate the serve
/// loop (ISSUE-KVD-CLI-330251).
///
/// Factored out of [`StdioTransport::read`] so the blank-line / EOF semantics
/// are unit-testable against an in-memory reader.
pub(crate) async fn read_request<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> KvendraResult<Option<JsonRpcRequest>> {
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Real EOF: the stdin pipe is closed.
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // Spurious blank line — do NOT treat as EOF. Keep reading.
            continue;
        }
        let req: JsonRpcRequest = serde_json::from_str(trimmed)
            .map_err(|e| KvendraError::McpProtocol(format!("parse: {e}")))?;
        return Ok(Some(req));
    }
}

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

    /// Read one JSON-RPC request line from stdin. See [`read_request`] for the
    /// blank-line / EOF semantics.
    pub async fn read(&mut self) -> KvendraResult<Option<JsonRpcRequest>> {
        read_request(&mut self.reader).await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(input: &str) -> tokio::io::BufReader<std::io::Cursor<Vec<u8>>> {
        tokio::io::BufReader::new(std::io::Cursor::new(input.as_bytes().to_vec()))
    }

    const REQ_A: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}}"#;
    const REQ_B: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b"}}"#;

    /// Regression guard for ISSUE-KVD-CLI-330251: a blank line between two
    /// valid requests must NOT terminate the stream. We must read A, skip the
    /// blank line(s), then read B, and only THEN hit EOF.
    #[tokio::test]
    async fn blank_line_between_requests_does_not_end_stream() {
        // Two requests separated by an empty line and a whitespace-only line.
        let input = format!("{REQ_A}\n\n   \n{REQ_B}\n");
        let mut r = reader(&input);

        let first = read_request(&mut r).await.unwrap();
        assert_eq!(first.unwrap().id, Some(serde_json::json!(1)));

        let second = read_request(&mut r).await.unwrap();
        assert_eq!(second.unwrap().id, Some(serde_json::json!(2)));

        // Now the underlying cursor is exhausted → real EOF.
        let third = read_request(&mut r).await.unwrap();
        assert!(third.is_none(), "expected EOF after the last request");
    }

    /// A leading blank line before the first request is skipped, not treated
    /// as EOF.
    #[tokio::test]
    async fn leading_blank_line_is_skipped() {
        let input = format!("\n{REQ_A}\n");
        let mut r = reader(&input);
        let first = read_request(&mut r).await.unwrap();
        assert_eq!(first.unwrap().id, Some(serde_json::json!(1)));
    }

    /// `read_line` returning `n == 0` (closed pipe) is the only real EOF and
    /// yields `Ok(None)`.
    #[tokio::test]
    async fn empty_input_is_eof() {
        let mut r = reader("");
        let res = read_request(&mut r).await.unwrap();
        assert!(res.is_none(), "empty input must be a clean EOF");
    }

    /// A blank-only stream is all spurious lines followed by EOF — it must
    /// terminate (Ok(None)) without looping forever and without parse errors.
    #[tokio::test]
    async fn only_blank_lines_then_eof() {
        let mut r = reader("\n  \n\t\n");
        let res = read_request(&mut r).await.unwrap();
        assert!(res.is_none());
    }
}
