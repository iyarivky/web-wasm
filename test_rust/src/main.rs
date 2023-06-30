use serde_json::{json, Result, Value};
use url::Url;

fn print_vmess_protocol(url: &Url) -> Value {
    let scheme = url.scheme();

    json!({
        "tag": "Ini config Vmess",
        "protocol": scheme
    })
}

fn print_vless_protocol(url: &Url) -> Value {
    let scheme = url.scheme();
    let fragment = url.fragment();

    json!({
        "tag": fragment,
        "protocol": scheme
    })
}

fn print_trojan_protocol(url: &Url) -> Value {
    let scheme = url.scheme();
    let fragment = url.fragment();

    json!({
        "tag": fragment,
        "protocol": scheme
    })
}

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

fn main() {
    let urls = [
        "vmess://eyJhZGQiOiAic2cyLXJheS5pcHNlcnZlcnMueHl6IiwgImhvc3QiOiAic25pLmNsb3VkZmxhcmUuY29tIiwgImFpZCI6IDAsICJ0eXBlIjogIiIsICJwYXRoIjogIi9KQUdPQU5TU0gvIiwgIm5ldCI6ICJ3cyIsICJwcyI6ICJqYWdvYW5zc2gtZ29kZGFtbiIsICJ0bHMiOiAidGxzIiwgInR5cGUiOiAibm9uZSIsICJwb3J0IjogIjQ0MyIsICJ2IjogIjIiLCAiaWQiOiAiNGE0NWU0NzctY2ZhMS00YTBmLWEwYjAtZTQ1MTczYzYyZjViIn0=",
        "vmess://eyJhZGQiOiJ1czIub2NlaXMubmV0IiwiYWlkIjoiMCIsImFscG4iOiIiLCJmcCI6IiIsImhvc3QiOiIiLCJpZCI6ImRhY2Y2MzQwLTA5ZmQtMTFlZS1iMjM2LTIwNWM2ZDVmNWQ3OCIsIm5ldCI6IndzIiwicGF0aCI6Ii92bXdzIiwicG9ydCI6IjQ0MyIsInBzIjoiVVNBK1ZNRVNTLVdTKDIwMjMtMDYtMjApIiwic2N5Ijoibm9uZSIsInNuaSI6IndoYXRzYXBwLm5ldCIsInRscyI6InRscyIsInR5cGUiOiIiLCJ2IjoiMiJ9",
        "vmess://eyJhZGQiOiJ1czIub2NlaXMubmV0IiwiYWlkIjoiMCIsImFscG4iOiIiLCJmcCI6IiIsImhvc3QiOiIiLCJpZCI6ImRhY2Y2MzQwLTA5ZmQtMTFlZS1iMjM2LTIwNWM2ZDVmNWQ3OCIsIm5ldCI6IndzIiwicGF0aCI6Ii92bXdzIiwicG9ydCI6IjgwIiwicHMiOiJVU0ErVk1FU1MtV1MgTlRMUygyMDIzLTA2LTIwKSIsInNjeSI6Im5vbmUiLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoiIiwidiI6IjIifQ==",
        "vless://a771070c-b93e-4f72-8747-657f4a41ead9@sglws.mainssh.xyz:443?path=/vless&security=tls&encryption=none&host=sglws.mainssh.xyz&type=ws&sni=sglws.mainssh.xyz#mainssh-legendo",
        "vless://d4cbf663-6950-4c64-8a52-f8b82a02e031@sg4-ws.xvless.xyz:80?path=%2Fwebsocket&security=none&encryption=none&host=sg4-ws.xvless.xyz&type=ws&sni=sni.cloudflare.net#sshocean-legendaplis",
        "vless://f746cd36-f565-444b-8bb8-6043c79eb3da@id1-grpc.xvless.xyz:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-legendano",
        "trojan://a758ef8c-f06c-4e9d-8f0b-51633db51817@idt6.sshocean.net:443?security=tls&headerType=none&type=tcp&sni=sni.cloudflare.net#sshocean-kenapalegenda_trojan",
        "trojan://6d9fdac3-d74b-435f-aa6b-5fbf36e06853@sg1.xvless.xyz:443?host=sg1.xvless.xyz&path=%2Ftrojan&sni=sg1.xvless.xyz&type=ws#sshocean-ainian",
        "trojan://dbedf072-d917-41cd-b106-3aa3bb2f29a4@idt4.sshocean.net:443?mode=gun&security=tls&type=grpc&serviceName=grpc&sni=sni.cloudflare.net#sshocean-pengentest_Trojan_gRPC"
    ];

    if let Err(e) = print_protocol_for_urls(&urls) {
        eprintln!("Error printing protocol: {}", e);
    }
}
