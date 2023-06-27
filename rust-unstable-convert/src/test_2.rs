use url::Url;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct ConfigResult {
    tag: String,
    r#type: String,
    server: String,
    server_port: u32,
    uuid: String,
    security: String,
    alter_id: String,
    global_padding: bool,
    authenticated_length: bool,
    multiplex: MultiplexInfo,
    tls: Option<TlsInfo>,
    transport: Option<TransportInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct MultiplexInfo {
    enable: bool,
    protocol: String,
    max_streams: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct TlsInfo {
    enable: bool,
    server_name: String,
    insecure: bool,
    disable_sni: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct TransportInfo {
    r#type: Option<String>,
    path: Option<String>,
    headers: Option<HeadersInfo>,
    service_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct HeadersInfo {
    Host: Option<String>,
}

fn parse_urls(vray_urls: Vec<String>, http_urls: Vec<String>) -> Vec<ConfigResult> {
    let results: Vec<ConfigResult> = vray_urls
        .into_iter()
        .zip(http_urls)
        .map(|(vray_string, http_string)| {
            let vray_parsed_url = Url::parse(&vray_string).unwrap();
            let http_parsed_url = Url::parse(&http_string).unwrap();

            let config_result = match vray_parsed_url.scheme() {
                "vmess" => parse_vmess_url(&vray_parsed_url, &http_parsed_url),
                "vless" => parse_vless_url(&vray_parsed_url, &http_parsed_url),
                "trojan" => parse_trojan_url(&vray_parsed_url, &http_parsed_url),
                "ss" => parse_shadowsocks_url(&vray_parsed_url, &http_parsed_url),
                "ssr" => parse_shadowsocksr_url(&vray_parsed_url, &http_parsed_url),
                "socks5" => parse_socks_url(&vray_parsed_url, &http_parsed_url),
                "http" => parse_http_url(&vray_parsed_url, &http_parsed_url),
                _ => {
                    println!("Unsupported Protocol!");
                    return None;
                }
            };

            config_result
        })
        .filter_map(|result| result)
        .collect();

    results
}

fn parse_vmess_url(vray_parsed_url: &Url, _http_parsed_url: &Url) -> Option<ConfigResult> {
    let encoded = vray_parsed_url.as_str()[8..].to_owned();
    let decode_result = base64::decode(&encoded).unwrap();
    let parsed_json: serde_json::Value = serde_json::from_slice(&decode_result).unwrap();

    let mut config_result = ConfigResult {
        tag: parsed_json["ps"].as_str()?.to_owned(),
        r#type: "vmess".to_owned(),
        server: parsed_json["add"].as_str()?.to_owned(),
        server_port: parsed_json["port"].as_u64()? as u32,
        uuid: parsed_json["id"].as_str()?.to_owned(),
        security: "auto".to_owned(),
        alter_id: parsed_json["aid"].as_u64()?.to_string(),
        global_padding: false,
        authenticated_length: true,
        multiplex: MultiplexInfo {
            enable: false,
            protocol: "smux".to_owned(),
            max_streams: 32,
        },
        tls: None,
        transport: None,
    };

    if parsed_json["port"].as_str()? == "443" || parsed_json["tls"].as_str()? == "tls" {
        config_result.tls = Some(TlsInfo {
            enable: true,
            server_name: parsed_json["sni"].as_str()?.to_owned(),
            insecure: true,
            disable_sni: false,
        });
    }

    if parsed_json["net"].as_str()? == "ws" {
        config_result.transport = Some(TransportInfo {
            r#type: Some(parsed_json["net"].as_str()?.to_owned()),
            path: Some(parsed_json["path"].as_str()?.to_owned()),
            headers: Some(HeadersInfo {
                Host: Some(parsed_json["host"].as_str()?.to_owned()),
            }),
            service_name: None,
        });
    } else if parsed_json["net"].as_str()? == "grpc" {
        config_result.transport = Some(TransportInfo {
            r#type: Some(parsed_json["net"].as_str()?.to_owned()),
            path: None,
            headers: None,
            service_name: Some(parsed_json["path"].as_str()?.to_owned()),
        });
    }

    Some(config_result)
}

fn parse_vless_url(vray_parsed_url: &Url, http_parsed_url: &Url) -> Option<ConfigResult> {
    let config_result = ConfigResult {
        tag: http_parsed_url.fragment().map_or_else(|| "".to_owned(), |s| s[1..].to_owned()),
        r#type: "vless".to_owned(),
        server: http_parsed_url.host_str()?.to_owned(),
        server_port: http_parsed_url.port()?,
        uuid: http_parsed_url.username().to_owned(),
        security: "".to_owned(),
        alter_id: "".to_owned(),
        global_padding: false,
        authenticated_length: false,
        multiplex: MultiplexInfo {
            enable: false,
            protocol: "smux".to_owned(),
            max_streams: 32,
        },
        tls: None,
        transport: None,
    };

    if http_parsed_url.port() == Some(443) || http_parsed_url.query_pairs().any(|(k, _)| k == "security" && _ == "tls") {
        let sni = http_parsed_url.query_pairs().find(|(k, _)| k == "sni").map(|(_, v)| v.to_owned());
        let tls_info = TlsInfo {
            enable: true,
            server_name: sni.clone().unwrap_or_else(|| http_parsed_url.host_str().unwrap().to_owned()),
            insecure: true,
            disable_sni: false,
        };

        Some(config_result)
    } else {
        Some(config_result)
    }
}

// Implement the other parsing functions (parse_trojan_url, parse_shadowsocks_url, etc.) similarly

fn main() {
    let vray_urls = vec![
        "vmess://eyJhZGQiOiAic2cyLXJheS5pcHNlcnZlcnMueHl6IiwgImhvc3QiOiAic25pLmNsb3VkZmxhcmUuY29tIiwgImFpZCI6IDAsICJ0eXBlIjogIiIsICJwYXRoIjogIi9KQUdPQU5TU0gvIiwgIm5ldCI6ICJ3cyIsICJwcyI6ICJqYWdvYW5zc2gtZ29kZGFtbiIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAibm9uZSIsICJwb3J0IjogIjQ0MyIsICJ2IjogIjIiLCAiaWQiOiAiNGE0NWU0NzctY2ZhMS00YTBmLWEwYjAtZTQ1MTczYzYyZjViIn0=",
        "vless://a771070c-b93e-4f72-8747-657f4a41ead9@sglws.mainssh.xyz:443?path=/vless&security=tls&encryption=none&host=sglws.mainssh.xyz&type=ws&sni=sglws.mainssh.xyz#mainssh-legendo",
        "trojan://6d9fdac3-d74b-435f-aa6b-5fbf36e06853@sg1.xvless.xyz:443?host=sg1.xvless.xyz&path=%2Ftrojan&sni=sg1.xvless.xyz&type=ws#sshocean-ainian",
        "trojan://dbedf072-d917-41cd-b106-3aa3bb2f29a4@idt4.sshocean.net:443?mode=gun&security=tls&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-pengentest_Trojan_gRPC",
    ];

    let http_urls = vray_urls
        .iter()
        .map(|url_string| url_string.replace_range(..url_string.find(':').unwrap_or(0), "ftp"))
        .collect::<Vec<_>>();

    let start_time = Instant::now();
    let results = parse_urls(&vray_urls, &http_urls);
    let end_time = Instant::now();
    let diff = end_time.duration_since(start_time);
    let json_result = serde_json::to_string_pretty(&results).unwrap();
    println!("{}", json_result);
    println!("{:?} ms", diff.as_millis());
}

/*
Note: This Rust code assumes that you have the `url` and `serde_json` crates added to your `Cargo.toml` file. You can add them like this:

```toml
[dependencies]
url = "2.2.2"
serde_json = "1.0.64"
*/