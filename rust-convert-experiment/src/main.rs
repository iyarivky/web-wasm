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

fn vless_convert(url_string: &str) -> Result<String, Box<dyn std::error::Error>> {
    match Url::parse(url_string) {
        Ok(url) => {
            let security = url.query_pairs().find(|(key, _)| key == "security").map(|(_, value)| value.to_string()).unwrap_or("".to_string());
            let server_name = url.query_pairs().find(|(key, _)| key == "sni").map(|(_, value)| value.to_string()).unwrap_or("".to_string());
            let transport_type = url.query_pairs().find(|(key, _)| key == "type").map(|(_, value)| value.to_string()).unwrap_or("".to_string());

            let url_info = VlessUrlInfo {
                tag: url.fragment().unwrap_or("").to_string(),
                r#type: url.scheme().to_string(),
                server: url.host_str().unwrap_or("").to_string(),
                server_port: url.port().unwrap_or(0),
                uuid: url.username().to_string(),
                flow: "".to_string(),
                packet_encoding: "xudp".to_string(),
                security: security.clone(),
                multiplex: MultiplexInfo {
                    enable: false,
                    protocol: "smux".to_string(),
                    max_stream: 32,
                },
                tls: if url.port().unwrap_or(0) == 443 || security == "tls" {
                    Some(TlsInfo {
                        enable: true,
                        server_name: server_name.clone(),
                        insecure: true,
                        disable_sni: false,
                    })
                } else {
                    None
                },
                transport: match transport_type.as_str() {
                    "ws" => Some(TransportInfo {
                        r#type: Some(transport_type.clone()),
                        path: url.query_pairs().find(|(key, _)| key == "path").map(|(_, value)| value.to_string()),
                        headers: Some(HeadersInfo {
                            Host: url.query_pairs().find(|(key, _)| key == "host").map(|(_, value)| value.to_string()).unwrap_or("".to_string()),
                        }),
                        service_name: None,
                    }),
                    "grpc" => Some(TransportInfo {
                        r#type: Some(transport_type.clone()),
                        path: None,
                        headers: None,
                        service_name: url.query_pairs().find(|(key, _)| key == "serviceName").map(|(_, value)| value.to_string()),
                    }),
                    _ => None,
                },
            };

            let json_string = serde_json::to_string_pretty(&url_info)?;
            Ok(json_string)
        },
        Err(e) => Err(format!("Terjadi kesalahan: {}", e).into()),
    }
}

fn main() {
    let url_string = "vless://a771070c-b93e-4f72-8747-657f4a41ead9@sglws.mainssh.xyz:443?path=/vless&security=tls&encryption=none&host=sglws.mainssh.xyz&type=ws&sni=sglws.mainssh.xyz#mainssh-legendo";

    match vless_convert(url_string) {
        Ok(json_string) => println!("{}", json_string),
        Err(e) => eprintln!("{}", e),
    }
}
