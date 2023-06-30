use url::Url;
use serde_derive::{Serialize, Deserialize};
use serde_json;

#[derive(Serialize, Deserialize)] //Multiplex
struct MultiplexInfo {
    enable: bool,
    protocol: String,
    max_stream: u16,
}

#[derive(Serialize, Deserialize)] //uTLS
struct UtlsInfo {
    enabled: bool,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)] // Reality Handshake
struct RealityHandshakeInfo {
  server: String,
  server_port: u16,
}

#[derive(Serialize, Deserialize)] // Reality
struct RealityInfo {
  enabled: bool,
  public_key: String,
}

#[derive(Serialize, Deserialize)] // TLS
struct TlsInfo {
    enable: bool,
    server_name: String,
    insecure: bool,
    disable_sni: bool,
    utls:UtlsInfo,
    reality:RealityInfo
}

#[derive(Serialize, Deserialize)] // V2Ray Transport (HTTP,WS,gRPC,QUIC)
struct V2rayTransportInfo {
    r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<HeadersInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_early_data: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    early_data_header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idle_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ping_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permit_without_stream: Option<bool>
}

#[derive(Serialize, Deserialize)] //for HTTP and V2Ray Transport (WS and HTTP)
#[allow(non_snake_case)]
struct HeadersInfo {
    Host: String,
}

#[derive(Serialize, Deserialize)] // UDP over TCP (for Shadowsocks and Socks)
struct UdpOverTcpInfo{
  enable: bool,
  version: u16
}

// all outbound

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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Serialize, Deserialize)]
struct ShadowsocksUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    method: String,
    password: String,
    plugin: String,
    plugin_opts: String,
    udp_over_tcp: UdpOverTcpInfo,
    multiplex: MultiplexInfo,
}

#[derive(Serialize, Deserialize)]
struct ShadowsocksRUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    password: String,
    transport: Option<TransportInfo>,
    tls: Option<TlsInfo>,
    multiplex: MultiplexInfo,
}

#[derive(Serialize, Deserialize)]
struct SocksUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    version: String,
    username: String,
    password: String,
    udp_over_tcp: UdpOverTcpInfo
}

#[derive(Serialize, Deserialize)]
struct HttpUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    username: String,
    password: String,
    path: String,
    headers: HeadersInfo,
    tls: Option<TlsInfo>
}

//try to figure how use function in rust

pub fn print_protocol_for_urls(urls: &[&str]) -> Result<()> {
    let mut output: Vec<Value> = Vec::new();

    for url_str in urls.iter() {
        match Url::parse(url_str) {
            Ok(url) => {
                let scheme = url.scheme();
                let json_obj = match scheme {
                    "vmess" => print_vmess_protocol(&url),
                    "vless" => print_vless_protocol(&url),
                    "trojan" => print_trojan_protocol(&url),
                    _ => {
                        eprintln!("Unsupported protocol: {}", scheme);
                        continue;
                    }
                };
                output.push(json_obj);
            }
            Err(e) => {
                eprintln!("Error parsing URL: {}", e);
            }
        }
    }

    let pretty_output = serde_json::to_string_pretty(&output)?;
    println!("{}", pretty_output);

    Ok(())
}

fn vmess_urls()
fn vless_urls()
fn trojan_urls()
fn shadowsocks_urls()
fn shadowsocksr_urls()
fn socks_urls()
fn http_urls()