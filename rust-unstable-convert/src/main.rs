use url::Url;
use serde_derive::{Serialize, Deserialize};
use serde_json;

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
struct VmessUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    uuid: String,
    security: String,
    alter_id: u16,
    global_padding: bool,
    authenticated_length: bool,
    packet_encoding: String,
    tls: Option<TlsInfo>,
    transport: Option<TransportInfo>,
    multiplex: MultiplexInfo,
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

#[derive(Serialize, Deserialize)]
struct TrojanUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    password: String,
    transport: Option<TransportInfo>,
    tls: Option<TlsInfo>,
    multiplex: MultiplexInfo,
}

//try to figure how use function in rust

fn parse_urls(vray_urls: Vec<String>) -> Vec<ConfigResult> {

}

fn vmess_urls()
fn vless_urls()
fn trojan_urls()
fn shadowsocks_urls()
fn shadowsocksr_urls()
fn socks_urls()
fn http_urls()