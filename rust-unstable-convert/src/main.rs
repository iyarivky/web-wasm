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
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<TransportInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    method: String,
    password: String,
    obfs: String,
    obfs_param: String,
    protocol: String
    protocol_param: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsInfo>
}

//Converter Function

fn vmess_urls_to_json()
fn vless_urls_to_json()
fn trojan_urls_to_json()
fn shadowsocks_urls_to_json()
fn shadowsocksr_urls_to_json()
fn socks_urls_to_json()
fn http_urls_to_json()

pub fn print_url_to_json(urls: &[&str]) -> Result<()> {
    let mut output: Vec<Value> = Vec::new();

    for url_str in urls.iter() {
        match Url::parse(url_str) {
            Ok(url) => {
                let scheme = url.scheme();
                let json_obj = match scheme {
                    "vmess" => vmess_urls_to_json(&url),
                    "vless" => vless_urls_to_json(&url),
                    "trojan" => trojan_urls_to_json(&url),
                    "ss" => shadowsocks_urls_to_json(&url),
                    "ssr" => shadowsocksr_urls_to_json()(&url),
                    "socks5" => socks_urls_to_json(&url),
                    "http" => http_urls_to_json(&url),
                    "https" => http_urls_to_json(&url),
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

fn main(){
  let vray_account = [
    "vmess://eyJhZGQiOiAic2cyLXJheS5pcHNlcnZlcnMueHl6IiwgImhvc3QiOiAic25pLmNsb3VkZmxhcmUuY29tIiwgImFpZCI6IDAsICJ0eXBlIjogIiIsICJwYXRoIjogIi9KQUdPQU5TU0gvIiwgIm5ldCI6ICJ3cyIsICJwcyI6ICJqYWdvYW5zc2gtZ29kZGFtbiIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAibm9uZSIsICJwb3J0IjogIjQ0MyIsICJ2IjogIjIiLCAiaWQiOiAiNGE0NWU0NzctY2ZhMS00YTBmLWEwYjAtZTQ1MTczYzYyZjViIn0=",
    "vless://a771070c-b93e-4f72-8747-657f4a41ead9@sglws.mainssh.xyz:443?path=/vless&security=tls&encryption=none&host=sglws.mainssh.xyz&type=ws&sni=sglws.mainssh.xyz#mainssh-legendo",
    "trojan://6d9fdac3-d74b-435f-aa6b-5fbf36e06853@sg1.xvless.xyz:443?host=sg1.xvless.xyz&path=%2Ftrojan&sni=sg1.xvless.xyz&type=ws#sshocean-ainian",
    "trojan://dbedf072-d917-41cd-b106-3aa3bb2f29a4@idt4.sshocean.net:443?mode=gun&security=tls&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-pengentest_Trojan_gRPC",
    ]

  let parsevray_to_json = 

}