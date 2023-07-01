use url::Url;
use serde_derive::{Serialize, Deserialize};
use serde_json::{json, Value};
use std::error::Error;
use std::result::Result;

#[derive(Serialize, Deserialize)]
struct MultiplexInfo {
    enable: bool,
    protocol: String,
    max_stream: u16,
}

#[derive(Serialize, Deserialize)]
struct UtlsInfo {
    enabled: bool,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct RealityHandshakeInfo {
    server: String,
    server_port: u16,
}

#[derive(Serialize, Deserialize)]
struct RealityInfo {
    enabled: bool,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct TlsInfo {
    enable: bool,
    server_name: String,
    insecure: bool,
    disable_sni: bool,
    utls: UtlsInfo,
    reality: RealityInfo,
}

#[derive(Serialize, Deserialize)]
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
    permit_without_stream: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct HeadersInfo {
    Host: String,
}

#[derive(Serialize, Deserialize)]
struct UdpOverTcpInfo {
    enable: bool,
    version: u16,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsInfo>,
    transport: Option<V2rayTransportInfo>,
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
    transport: Option<V2rayTransportInfo>,
}

#[derive(Serialize, Deserialize)]
struct TrojanUrlInfo {
    tag: String,
    r#type: String,
    server: String,
    server_port: u16,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<V2rayTransportInfo>,
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
    protocol: String,
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
    udp_over_tcp: UdpOverTcpInfo,
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
    tls: Option<TlsInfo>,
}

fn vmess_urls_to_json(url: &Url) -> Result<Value, Box<dyn Error>> {
    let info = VmessUrlInfo {
        tag: "".to_string(),
        r#type: "".to_string(),
        server: "".to_string(),
        server_port: 0,
        uuid: "".to_string(),
        security: "".to_string(),
        alter_id: 0,
        global_padding: false,
        authenticated_length: false,
        packet_encoding: "".to_string(),
        tls: None,
        transport: None,
        multiplex: MultiplexInfo {
            enable: false,
            protocol: "".to_string(),
            max_stream: 0,
        },
    };
    let json_obj = json!(info);
    Ok(json_obj)
}

fn vless_urls_to_json(url: &Url) -> Result<Value, Box<dyn Error>> {
    let info = VlessUrlInfo {
        tag: "".to_string(),
        r#type: "".to_string(),
        server: "".to_string(),
        server_port: 0,
        uuid: "".to_string(),
        flow: "".to_string(),
        packet_encoding: "".to_string(),
        security: "".to_string(),
        multiplex: MultiplexInfo {
            enable: false,
            protocol: "".to_string(),
            max_stream: 0,
        },
        tls: None,
        transport: None,
    };
    let json_obj = json!(info);
    Ok(json_obj)
}

fn trojan_urls_to_json(url: &Url) -> Result<Value, Box<dyn Error>> {
    let info = TrojanUrlInfo {
        tag: "".to_string(),
        r#type: "".to_string(),
        server: "".to_string(),
        server_port: 0,
        password: "".to_string(),
        transport: None,
        tls: None,
        multiplex: MultiplexInfo {
            enable: false,
            protocol: "".to_string(),
            max_stream: 0,
        },
    };
    let json_obj = json!(info);
    Ok(json_obj)
}

fn shadowsocks_urls_to_json(url: &Url) -> Result<Value, Box<dyn Error>> {
    let info = ShadowsocksUrlInfo {
        tag: "".to_string(),
        r#type: "".to_string(),
        server: "".to_string(),
        server_port: 0,
        method: "".to_string(),
        password: "".to_string(),
        plugin: "".to_string(),
        plugin_opts: "".to_string(),
        udp_over_tcp: UdpOverTcpInfo {
            enable: false,
            version: 0,
        },
        multiplex: MultiplexInfo {
            enable: false,
            protocol: "".to_string(),
            max_stream: 0,
        },
    };
    let json_obj = json!(info);
    Ok(json_obj)
}

fn shadowsocksr_urls_to_json(url: &Url) -> Result<Value, Box<dyn Error>> {
    let info = ShadowsocksRUrlInfo {
        tag: "".to_string(),
        r#type: "".to_string(),
        server: "".to_string(),
        server_port: 0,
        method: "".to_string(),
        password: "".to_string(),
        obfs: "".to_string(),
        obfs_param: "".to_string(),
        protocol: "".to_string(),
        protocol_param: "".to_string(),
    };
    let json_obj = json!(info);
    Ok(json_obj)
}

fn socks_urls_to_json(url: &Url) -> Result<Value, Box<dyn Error>> {
    let info = SocksUrlInfo {
        tag: "".to_string(),
        r#type: "".to_string(),
        server: "".to_string(),
        server_port: 0,
        version: "".to_string(),
        username: "".to_string(),
        password: "".to_string(),
        udp_over_tcp: UdpOverTcpInfo {
            enable: false,
            version: 0,
        },
    };
    let json_obj = json!(info);
    Ok(json_obj)
}

fn http_urls_to_json(url: &Url) -> Result<Value, Box<dyn Error>> {
    let info = HttpUrlInfo {
        tag: "".to_string(),
        r#type: "".to_string(),
        server: "".to_string(),
        server_port: 0,
        username: "".to_string(),
        password: "".to_string(),
        path: "".to_string(),
        headers: HeadersInfo {
            Host: "".to_string(),
        },
        tls: None,
    };
    let json_obj = json!(info);
    Ok(json_obj)
}

pub fn print_url_to_json(urls: &[&str]) -> Result<(), Box<dyn Error>> {
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
                    "ssr" => shadowsocksr_urls_to_json(&url),
                    "socks5" => socks_urls_to_json(&url),
                    "http" | "https" => http_urls_to_json(&url),
                    _ => {
                        eprintln!("Unsupported protocol: {}", scheme);
                        continue;
                    }
                };
                match json_obj {
                    Ok(json) => output.push(json),
                    Err(e) => {
                        eprintln!("Error converting URL to JSON: {}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error parsing URL: {}", e);
                continue;
            }
        }
    }

    let pretty_output = serde_json::to_string_pretty(&output)?;
    println!("{}", pretty_output);

    Ok(())
}

fn main() {
    let urls = [
        "vmess://...",
        "vless://...",
        "trojan://...",
        "ss://...",
        "ssr://...",
        "socks5://...",
        "http://...",
    ];

    if let Err(e) = print_url_to_json(&urls) {
        eprintln!("Error: {}", e);
    }
}