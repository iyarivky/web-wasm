use serde_json::{json, to_string_pretty};
use url::Url;

fn main() {
    let urls = [
        "vless://a771070c-b93e-4f72-8747-657f4a41ead9@sglws.mainssh.xyz:443?path=/vless&security=tls&encryption=none&host=sglws.mainssh.xyz&type=ws&sni=sglws.mainssh.xyz#mainssh-legendo",
        "vless://d4cbf663-6950-4c64-8a52-f8b82a02e031@sg4-ws.xvless.xyz:80?path=%2Fwebsocket&security=none&encryption=none&host=sg4-ws.xvless.xyz&type=ws&sni=sni.cloudflare.net#sshocean-legendaplis",
        "vless://f746cd36-f565-444b-8bb8-6043c79eb3da@id1-grpc.xvless.xyz:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-legendano",
        "trojan://a758ef8c-f06c-4e9d-8f0b-51633db51817@idt6.sshocean.net:443?security=tls&headerType=none&type=tcp&sni=sni.cloudflare.net#sshocean-kenapalegenda_trojan",
        "trojan://6d9fdac3-d74b-435f-aa6b-5fbf36e06853@sg1.xvless.xyz:443?host=sg1.xvless.xyz&path=%2Ftrojan&sni=sg1.xvless.xyz&type=ws#sshocean-ainian",
        "trojan://dbedf072-d917-41cd-b106-3aa3bb2f29a4@idt4.sshocean.net:443?mode=gun&security=tls&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-pengentest_Trojan_gRPC"
    ];

    for url_str in urls {
        let url = Url::parse(url_str).unwrap();
        let mut config = match url.scheme() {
            "vless" => json!({
                "domain_strategy": "ipv4_only",
                "type": url.scheme(),
                "tag": url.fragment().unwrap(),
                "server": url.host_str().unwrap(),
                "server_port": url.port().unwrap(),
                "uuid": url.username(),
                "security": "auto",
                "multiplex": {
                    "enabled": false,
                    "protocol": "smux",
                    "max_streams": 32
                }
            }),
            "trojan" => json!({
                "domain_strategy": "ipv4_only",
                "type": url.scheme(),
                "tag": url.fragment().unwrap(),
                "server": url.host_str().unwrap(),
                "server_port": url.port().unwrap(),
                "password": url.username(),            
                "multiplex": {
                    "enabled": false,
                    "protocol": "smux",
                    "max_streams": 32
                }
            }),
            _ => panic!("Unsupported protocol")
        };

        if (url.port().unwrap() == 443) || (url.query_pairs().find(|(k, _)| k == &"security").map(|(_, v)| v.to_string()) == Some("tls".to_string())) {
            config["tls"] = json!({
                "enabled": true,
                "server_name": url.query_pairs().find(|(k, _)| k == &"sni").map(|(_, v)| v.to_string()).unwrap_or("".to_string()),
                "insecure": true
            });
        }

        match url.query_pairs().find(|(k, _)| k == &"type").map(|(_, v)| v.to_string()) {
            Some(t) if t == *"ws" => {
                config["transport"] = json!({
                    "type": t,
                    "path": url.query_pairs().find(|(k, _)| k == &"path").map(|(_, v)| v.to_string()).unwrap_or("".to_string()),
                    "max_early_data": 0,
                    "early_data_header_name": "Sec-WebSocket-Protocol",
                    "headers": {
                        "Host": url.query_pairs().find(|(k, _)| k == &"host").map(|(_, v)| v.to_string()).unwrap_or("".to_string())
                    }
                });
            },
            Some(t) if t == *"grpc" => {
                config["transport"] = json!({
                    "type": t,
                    "service_name": url.query_pairs().find(|(k, _)| k == &"serviceName").map(|(_, v)| v.to_string()).unwrap_or("".to_string()),
                    "idle_timeout": "15s",
                    "ping_timeout": "15s",
                    "permit_without_stream": false
                });
            },
            _ => {}
        }

        println!("{}", to_string_pretty(&config).unwrap());
    }
}