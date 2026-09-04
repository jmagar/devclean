use crate::inventory::{
    DockerBackend, DockerDaemonKey, DockerObject, DockerObjectKind, DockerPage,
};
use devclean_core::CoverageStatus;
use serde_json::Value;
use socket2::{Domain, SockAddr, Socket, Type};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct DockerUnixBackend {
    connect_timeout: Duration,
    response_timeout: Duration,
    response_limit: u64,
}

impl DockerUnixBackend {
    pub fn new(connect_timeout: Duration, response_timeout: Duration, response_limit: u64) -> Self {
        Self {
            connect_timeout,
            response_timeout,
            response_limit,
        }
    }

    fn get(&self, key: &DockerDaemonKey, path: &str) -> Result<Vec<u8>, String> {
        let socket_path = key
            .transport
            .strip_prefix("unix://")
            .ok_or("only approved unix Docker transports are supported")?;
        if path
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | b' '))
        {
            return Err("invalid Docker API path".into());
        }
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(redact)?;
        socket
            .connect_timeout(
                &SockAddr::unix(socket_path).map_err(redact)?,
                self.connect_timeout,
            )
            .map_err(redact)?;
        let owned: OwnedFd = socket.into();
        let mut stream = UnixStream::from(owned);
        stream
            .set_read_timeout(Some(self.response_timeout))
            .map_err(redact)?;
        stream
            .set_write_timeout(Some(self.response_timeout))
            .map_err(redact)?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
        )
        .map_err(redact)?;
        let mut response = Vec::new();
        std::io::Read::by_ref(&mut stream)
            .take(self.response_limit.saturating_add(1))
            .read_to_end(&mut response)
            .map_err(redact)?;
        if response.len() as u64 > self.response_limit {
            return Err("Docker response exceeded limit".into());
        }
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or("malformed Docker HTTP response")?;
        let headers = &response[..header_end];
        if !headers.starts_with(b"HTTP/1.1 200") && !headers.starts_with(b"HTTP/1.0 200") {
            return Err("Docker API returned non-success".into());
        }
        let body = response[(header_end + 4)..].to_vec();
        if String::from_utf8_lossy(headers)
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            decode_chunked(&body)
        } else {
            Ok(body)
        }
    }
}

impl DockerBackend for DockerUnixBackend {
    fn identity(&mut self, key: &DockerDaemonKey) -> Result<String, String> {
        let body = self.get(key, "/info")?;
        let value: Value = serde_json::from_slice(&body).map_err(|_| "malformed Docker JSON")?;
        required_text(&value, "ID")
    }

    fn epoch(&mut self, key: &DockerDaemonKey) -> Result<String, String> {
        let body = self.get(key, "/system/df")?;
        let value: Value = serde_json::from_slice(&body).map_err(|_| "malformed Docker JSON")?;
        let mut stable = Vec::new();
        for container in required_array(&value, "Containers")? {
            stable.push(format!(
                "container:{}:{}:{}",
                required_text(container, "Id")?,
                required_text(container, "Image")?,
                required_text(container, "State")?
            ));
        }
        for image in required_array(&value, "Images")? {
            stable.push(format!(
                "image:{}:{}",
                required_text(image, "Id")?,
                image
                    .get("Containers")
                    .and_then(Value::as_i64)
                    .unwrap_or(-1)
            ));
        }
        for volume in required_array(&value, "Volumes")? {
            let references = volume
                .get("UsageData")
                .and_then(Value::as_object)
                .and_then(|usage| usage.get("RefCount"))
                .and_then(Value::as_i64)
                .ok_or("Docker volume RefCount schema drift")?;
            stable.push(format!(
                "volume:{}:{references}",
                required_text(volume, "Name")?
            ));
        }
        for cache in required_array(&value, "BuildCache")? {
            stable.push(format!(
                "cache:{}:{}:{}",
                required_text(cache, "ID")?,
                required_bool(cache, "InUse")?,
                required_bool(cache, "Shared")?
            ));
        }
        stable.sort();
        Ok(blake3::hash(stable.join("\0").as_bytes())
            .to_hex()
            .to_string())
    }

    fn page(&mut self, key: &DockerDaemonKey, cursor: Option<&str>) -> Result<DockerPage, String> {
        let (path, next) = match cursor {
            None => ("/system/df", Some("networks".into())),
            Some("networks") => ("/networks", None),
            Some(_) => return Err("unknown Docker inventory cursor".into()),
        };
        let body = self.get(key, path)?;
        let value: Value = serde_json::from_slice(&body).map_err(|_| "malformed Docker JSON")?;
        let objects = if cursor.is_none() {
            parse_disk_usage(&value)
        } else {
            parse_networks(&value)
        }?;
        Ok(DockerPage {
            objects,
            next,
            response_bytes: body.len() as u64,
        })
    }
}

fn object(
    id: String,
    kind: DockerObjectKind,
    size: u64,
    references: Vec<String>,
    compose_project: Option<String>,
) -> DockerObject {
    DockerObject {
        id,
        kind,
        size,
        references,
        compose_project,
        running: false,
        dangling: false,
        active_build: false,
        recently_used: false,
        shared_group: None,
        coverage: CoverageStatus::Complete,
        snapshot_fingerprint: String::new(),
    }
}

fn parse_disk_usage(root: &Value) -> Result<Vec<DockerObject>, String> {
    root.as_object().ok_or("Docker disk-usage schema drift")?;
    let mut objects = Vec::new();
    let mut image_consumers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for value in required_array(root, "Containers")? {
        let container_id = required_text(value, "Id")?;
        let image_id = required_text(value, "Image")?;
        image_consumers
            .entry(image_id.clone())
            .or_default()
            .push(container_id.clone());
        let (size, size_complete) = match value.get("SizeRw") {
            Some(Value::Number(number)) => (
                number
                    .as_u64()
                    .ok_or("Docker container SizeRw schema drift")?,
                true,
            ),
            None | Some(Value::Null) => (0, false),
            _ => return Err("Docker container SizeRw schema drift".into()),
        };
        let mut item = object(
            container_id,
            DockerObjectKind::Container,
            size,
            vec![image_id],
            label(value),
        );
        if !size_complete {
            item.coverage = CoverageStatus::Partial;
        }
        item.running = required_text(value, "State")? == "running";
        objects.push(item);
    }
    for value in required_array(root, "Images")? {
        let tags: Vec<String> = match value.get("RepoTags") {
            Some(Value::Null) => Vec::new(),
            Some(Value::Array(values)) => values
                .iter()
                .map(|tag| {
                    tag.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "Docker image RepoTags schema drift".to_owned())
                })
                .collect::<Result<_, _>>()?,
            _ => return Err("Docker image RepoTags schema drift".into()),
        };
        let image_id = required_text(value, "Id")?;
        let mut item = object(
            image_id.clone(),
            DockerObjectKind::Image,
            required_number(value, "Size")?,
            image_consumers.remove(&image_id).unwrap_or_default(),
            None,
        );
        item.dangling = tags.is_empty();
        let shared = required_number(value, "SharedSize")?;
        if shared > 0 {
            let mut layer = object(
                format!("shared:{}", item.id),
                DockerObjectKind::Layer,
                shared,
                vec![item.id.clone()],
                None,
            );
            // `/system/df` reports only aggregate shared bytes, not layer IDs.
            // Keep the estimate candidate-local and explicitly non-authoritative.
            layer.coverage = CoverageStatus::Partial;
            objects.push(layer);
        }
        objects.push(item);
    }
    for value in required_array(root, "Volumes")? {
        let usage = value
            .get("UsageData")
            .and_then(Value::as_object)
            .ok_or("Docker volume UsageData schema drift")?;
        let refs = usage
            .get("RefCount")
            .and_then(Value::as_u64)
            .ok_or("Docker volume RefCount schema drift")?;
        objects.push(object(
            required_text(value, "Name")?,
            DockerObjectKind::Volume,
            usage
                .get("Size")
                .and_then(Value::as_u64)
                .ok_or("Docker volume Size schema drift")?,
            (refs > 0).then(|| "attached".into()).into_iter().collect(),
            label(value),
        ));
    }
    for value in required_array(root, "BuildCache")? {
        let mut item = object(
            required_text(value, "ID")?,
            DockerObjectKind::BuildCache,
            required_number(value, "Size")?,
            vec![],
            None,
        );
        item.active_build = required_bool(value, "InUse")?;
        item.shared_group = required_bool(value, "Shared")?.then(|| item.id.clone());
        item.recently_used = match value.get("LastUsedAt") {
            Some(Value::Number(number)) => number.as_i64().is_some_and(|value| value > 0),
            Some(Value::String(value)) => !value.is_empty(),
            Some(Value::Null) => false,
            _ => return Err("Docker build-cache LastUsedAt schema drift".into()),
        };
        objects.push(item);
    }
    Ok(objects)
}

fn parse_networks(root: &Value) -> Result<Vec<DockerObject>, String> {
    root.as_array()
        .ok_or("Docker networks schema drift")?
        .iter()
        .map(|value| {
            let references = match value.get("Containers") {
                Some(Value::Object(values)) => values.keys().cloned().collect(),
                None | Some(Value::Null) => Vec::new(),
                _ => return Err("Docker network Containers schema drift".to_owned()),
            };
            Ok(object(
                required_text(value, "Id")?,
                DockerObjectKind::Network,
                0,
                references,
                label(value),
            ))
        })
        .collect::<Result<Vec<_>, String>>()
}
fn required_array<'a>(root: &'a Value, key: &str) -> Result<&'a [Value], String> {
    root.get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Docker {key} schema drift"))
}
fn required_text(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("Docker {key} schema drift"))
}
fn required_number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("Docker {key} schema drift"))
}
fn required_bool(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("Docker {key} schema drift"))
}
fn label(value: &Value) -> Option<String> {
    value
        .get("Labels")?
        .get("com.docker.compose.project")?
        .as_str()
        .map(str::to_owned)
}

fn redact(error: std::io::Error) -> String {
    format!("Docker transport error: {:?}", error.kind())
}

fn decode_chunked(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut rest = bytes;
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("malformed chunk")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&rest[..line_end])
                .map_err(|_| "malformed chunk")?
                .split(';')
                .next()
                .unwrap_or(""),
            16,
        )
        .map_err(|_| "malformed chunk")?;
        rest = &rest[(line_end + 2)..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size + 2 {
            return Err("short chunk".into());
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[(size + 2)..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_schema_drift_fails_closed() {
        assert!(parse_disk_usage(&serde_json::json!({})).is_err());
        assert!(parse_networks(&serde_json::json!({})).is_err());
        assert!(
            parse_disk_usage(&serde_json::json!({
                "Containers": [{}], "Images": [], "Volumes": [], "BuildCache": []
            }))
            .is_err()
        );
        assert!(
            parse_disk_usage(&serde_json::json!({
                "Containers": [],
                "Images": [{"Id": "i", "RepoTags": [7], "Size": 1, "SharedSize": 0}],
                "Volumes": [], "BuildCache": []
            }))
            .is_err()
        );
        assert!(
            parse_disk_usage(&serde_json::json!({
                "Containers": [], "Images": [], "Volumes": [],
                "BuildCache": [{"ID":"b", "Size":1, "InUse":null, "Shared":false, "LastUsedAt":0}]
            }))
            .is_err()
        );
        assert!(parse_networks(&serde_json::json!([{"Id":"n", "Containers":7}])).is_err());
    }
}
