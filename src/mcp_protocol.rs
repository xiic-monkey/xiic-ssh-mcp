use std::io::{BufRead, BufReader, Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageFraming {
    Newline,
    ContentLength,
}

#[derive(Debug)]
pub struct IncomingMessage {
    pub payload: Value,
    pub framing: MessageFraming,
}

pub fn read_message<R>(reader: &mut BufReader<R>) -> Result<Option<IncomingMessage>>
where
    R: Read,
{
    let mut content_length = None;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .context("failed to read MCP message")?;
        if bytes_read == 0 {
            return Ok(None);
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            let value = serde_json::from_str(trimmed)
                .context("failed to parse newline-delimited MCP JSON-RPC message")?;
            return Ok(Some(IncomingMessage {
                payload: value,
                framing: MessageFraming::Newline,
            }));
        }

        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            let parsed = value
                .trim()
                .parse::<usize>()
                .context("invalid Content-Length header")?;
            content_length = Some(parsed);
            break;
        }

        if trimmed.split_once(':').is_some() {
            break;
        }

        bail!("invalid MCP message start");
    }

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .context("failed to read MCP header")?;
        if bytes_read == 0 {
            bail!("unexpected EOF while reading MCP headers");
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }

        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            let parsed = value
                .trim()
                .parse::<usize>()
                .context("invalid Content-Length header")?;
            content_length = Some(parsed);
        }
    }

    let content_length = content_length.ok_or_else(|| anyhow!("missing Content-Length header"))?;
    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .context("failed to read MCP message body")?;

    let value =
        serde_json::from_slice(&body).context("failed to parse MCP JSON-RPC message body")?;
    Ok(Some(IncomingMessage {
        payload: value,
        framing: MessageFraming::ContentLength,
    }))
}

pub fn write_message<W>(writer: &mut W, payload: &Value, framing: MessageFraming) -> Result<()>
where
    W: Write,
{
    let body = serde_json::to_vec(payload).context("failed to serialize MCP response")?;
    match framing {
        MessageFraming::Newline => {
            writer
                .write_all(&body)
                .context("failed to write MCP response body")?;
            writer
                .write_all(b"\n")
                .context("failed to write MCP response newline")?;
        }
        MessageFraming::ContentLength => {
            write!(writer, "Content-Length: {}\r\n\r\n", body.len())
                .context("failed to write MCP response header")?;
            writer
                .write_all(&body)
                .context("failed to write MCP response body")?;
        }
    }
    writer.flush().context("failed to flush MCP response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use serde_json::json;

    use super::{MessageFraming, read_message, write_message};

    fn initialize_payload() -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test",
                    "version": "0.0.0"
                }
            }
        })
    }

    #[test]
    fn reads_newline_delimited_message() {
        let input = format!("{}\n", initialize_payload());
        let mut reader = BufReader::new(Cursor::new(input.into_bytes()));

        let message = read_message(&mut reader).unwrap().unwrap();

        assert_eq!(message.framing, MessageFraming::Newline);
        assert_eq!(message.payload["method"], "initialize");
    }

    #[test]
    fn reads_content_length_message() {
        let body = initialize_payload().to_string();
        let input = format!("Content-Length: {}\r\n\r\n{}", body.len(), body);
        let mut reader = BufReader::new(Cursor::new(input.into_bytes()));

        let message = read_message(&mut reader).unwrap().unwrap();

        assert_eq!(message.framing, MessageFraming::ContentLength);
        assert_eq!(message.payload["method"], "initialize");
    }

    #[test]
    fn writes_newline_delimited_response() {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let mut output = Vec::new();

        write_message(&mut output, &payload, MessageFraming::Newline).unwrap();

        assert!(output.ends_with(b"\n"));
        assert!(!output.starts_with(b"Content-Length:"));
        let parsed: serde_json::Value =
            serde_json::from_slice(output.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn writes_content_length_response() {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let mut output = Vec::new();

        write_message(&mut output, &payload, MessageFraming::ContentLength).unwrap();

        let output = String::from_utf8(output).unwrap();
        let (header, body) = output.split_once("\r\n\r\n").unwrap();
        let length = header
            .strip_prefix("Content-Length: ")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(length, body.len());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            payload
        );
    }
}
