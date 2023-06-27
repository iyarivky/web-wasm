extern crate url;
use std::str::FromStr;
use url::{Url, UrlParser};

fn parse_urls(url_strings: &[&str]) -> Vec<ConfigResult> {
    let mut results = Vec::new();

    fn parse_vmess_url(parsed_url: &Url) -> ConfigResult {
        let encoded = parsed_url.as_str()[8..].to_owned();
        let decode_result = base64::decode(encoded).unwrap();
        let parsed_json = serde_json::from_slice(&decode_result).unwrap();

        let config_result = ConfigResult {
            tag: parsed_json["ps"].as_str().unwrap().to_owned(),
            type: "vmess".to_owned(),
            server: parsed_json["add"].as_str().unwrap().to_owned(),
            server_port: parsed_json["port"].as_u64().unwrap() as u32,
            uuid: parsed_json["id"].as_str().unwrap().to_owned(),
            security: "auto".to_owned(),
            alter_id: parsed_json["aid"].as_u64().unwrap() as u32,
            global_padding: false,
            authenticated_length: true,
            multiplex: MultiplexConfig {
                enable: false,
                protocol: "smux".to_owned(),
                max_streams: 32,
            },
            tls: None,
            transport: None,
        };

        if parsed_json["port"].as_u64().unwrap() == 443 || parsed_json["tls"] == "tls" {
            let mut tls_config = TlsConfig {
                enable: true,
                server_name: parsed_json["sni"].as_str().unwrap_or("").to_owned(),
                insecure: true,
                disable_sni: false,
            };

            config_result.tls = Some(tls_config);
        }

        if parsed_json["net"] == "ws" {
            let mut transport_config = TransportConfig {
                type_: parsed_json["net"].as_str().unwrap().to_owned(),
                path: parsed_json["path"].as_str().unwrap().to_owned(),
                headers: Some(HeadersConfig {
                    Host: parsed_json["host"]
                        .as_str()
                        .unwrap_or(parsed_json["add"].as_str().unwrap())
                        .to_owned(),
                }),
            };

            config_result.transport = Some(transport_config);
        } else if parsed_json["net"] == "grpc" {
            let mut transport_config = TransportConfig {
                type_: parsed_json["net"].as_str().unwrap().to_owned(),
                service_name: parsed_json["path"].as_str().unwrap().to_owned(),
                headers: None,
            };

            config_result.transport = Some(transport_config);
        }

        config_result
    }

    // Implement the other parse_*_url functions

    for url_string in url_strings {
        let parsed_url = UrlParser::new()
            .base_url(None)
            .parse(url_string)
            .unwrap();
        let protocol = parsed_url.scheme();
        
        let config_result = match protocol {
            "vmess:" => parse_vmess_url(&parsed_url),
            _ => unimplemented!(),
        };

        results.push(config_result);
    }

    results
}

struct ConfigResult {
    tag: String,
    type_: String,
    server: String,
    server_port: u32,
    uuid: String,
    security: String,
    alter_id: u32,
    global_padding: bool,
    authenticated_length: bool,
    multiplex: MultiplexConfig,
    tls: Option<TlsConfig>,
    transport: Option<TransportConfig>,
}

struct MultiplexConfig {
    enable: bool,
    protocol: String,
    max_streams: u32,
}