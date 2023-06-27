// The wasm-pack uses wasm-bindgen to build and generate JavaScript binding file.
// Import the wasm-bindgen crate.
use url::Url;
use serde_derive::{Serialize, Deserialize};
use serde_json;
use wasm_bindgen::prelude::*;

// Our Add function
// wasm-pack requires "exported" functions
// to include #[wasm_bindgen]

#[derive(Serialize, Deserialize)]
struct MultiplexInfo {
    enable: bool,
    protocol: String,
    max_stream: u32,
}

#[derive(Serialize, Deserialize)]
struct TlsInfo {
    enable: bool,
    server_name: String,
    insecure: bool,
    disable_sni: bool,
}

#[derive(Serialize, Deserialize)]
struct TransportInfo {
    r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<HeadersInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct HeadersInfo {
    Host: String,
}

#[derive(Serialize, Deserialize)]
struct VlessUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    uuid: String,
    flow: String,
    packet_encoding: String,
    security: String,
    multiplex: MultiplexInfo,
    tls: Option<TlsInfo>,
    transport: Option<TransportInfo>,
}

#[wasm_bindgen]
pub fn vless_convert(a: i32, b: i32) -> i32 {
  return a + b;
}