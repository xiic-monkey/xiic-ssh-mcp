use std::io::{BufRead, BufReader, Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

const MAX_MCP_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

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

    loop {
        let Some(line) = read_line_limited(reader, "MCP message")? else {
            return Ok(None);
        };

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if trimmed.len() > MAX_MCP_MESSAGE_BYTES {
                bail!("MCP message exceeds the 16 MiB limit");
            }
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
            if parsed > MAX_MCP_MESSAGE_BYTES {
                bail!("MCP message exceeds the 16 MiB limit");
            }
            content_length = Some(parsed);
            break;
        }

        if trimmed.split_once(':').is_some() {
            break;
        }

        bail!("invalid MCP message start");
    }

    loop {
        let Some(line) = read_line_limited(reader, "MCP header")? else {
            bail!("unexpected EOF while reading MCP headers");
        };

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
            if parsed > MAX_MCP_MESSAGE_BYTES {
                bail!("MCP message exceeds the 16 MiB limit");
            }
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

fn read_line_limited<R>(reader: &mut BufReader<R>, label: &str) -> Result<Option<String>>
where
    R: Read,
{
    let mut bytes = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .with_context(|| format!("failed to read {label}"))?;
        if buffer.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }

        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        if bytes.len() + consumed > MAX_MCP_MESSAGE_BYTES + 2 {
            bail!("MCP message exceeds the 16 MiB limit");
        }
        bytes.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed);

        if newline.is_some() {
            break;
        }
    }

    String::from_utf8(bytes)
        .map(Some)
        .context("MCP message is not valid UTF-8")
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

    use super::{MAX_MCP_MESSAGE_BYTES, MessageFraming, read_message, write_message};

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
    fn rejects_oversized_content_length_before_allocating_body() {
        let input = format!("Content-Length: {}\r\n\r\n", MAX_MCP_MESSAGE_BYTES + 1);
        let mut reader = BufReader::new(Cursor::new(input.into_bytes()));

        let error = read_message(&mut reader).expect_err("oversized message should fail");

        assert!(error.to_string().contains("16 MiB"));
    }

    #[test]
    fn rejects_oversized_newline_delimited_message() {
        let mut input = vec![b' '; MAX_MCP_MESSAGE_BYTES + 1];
        input[0] = b'{';
        input.push(b'\n');
        let mut reader = BufReader::new(Cursor::new(input));

        let error = read_message(&mut reader).expect_err("oversized message should fail");

        assert!(error.to_string().contains("16 MiB"));
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
