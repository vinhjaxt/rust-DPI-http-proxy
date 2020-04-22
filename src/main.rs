#![deny(warnings)]
// Original from: https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs
use futures_util::future::try_join;

use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, Method, Request, Response, Server};
use hyper_tls::HttpsConnector;
use std::convert::Infallible;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_io_timeout::TimeoutReader;

use async_std::sync::{Arc, RwLock};
use clap::{value_t, Arg};
use std::collections::HashMap;
use twoway::find_bytes;
extern crate ajson;
#[macro_use]
extern crate lazy_static;

type HttpClient = Client<hyper::client::HttpConnector>;
type HttpsClient = Client<HttpsConnector<hyper::client::HttpConnector>>;
static mut DOH_ENDPOINT: &'static str = "https://1.1.1.1/dns-query";

#[derive(Clone)]
struct CacheResolver {
    map: Arc<RwLock<HashMap<String, IpAddr>>>,
}
impl CacheResolver {
    pub async fn get(&self, k: &String) -> Option<IpAddr> {
        match self.map.read().await.get(k) {
            None => None,
            Some(v) => Some(*v),
        }
    }
    pub async fn set(&self, k: String, v: IpAddr) {
        self.map.write().await.insert(k, v);
    }
}
lazy_static! {
    static ref IP_CACHE: CacheResolver = {
        CacheResolver {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    };
}

// To try this example:
// 1. cargo run -p 8080
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8080
//    $ export https_proxy=http://127.0.0.1:8080
// 3. send requests
//    $ curl -i https://www.some_domain.com/
// 4. or
//    $ curl -x http://127.0.0.1:8080 https://echo.opera.com/
#[tokio::main]
async fn main() {
    let matches = clap::App::new("Rust DPI bypass - HTTP Proxy v2.0.0")
        .arg(
            Arg::with_name("port")
                .short("p")
                .takes_value(true)
                .help("Listen port: Eg. 8080")
                .required(true),
        )
        .arg(
            Arg::with_name("doh")
                .short("d")
                .help(
                    format!("Change DNS over HTTPS endpoint: Eg. {}", unsafe {
                        DOH_ENDPOINT
                    })
                    .as_str(),
                )
                .takes_value(true)
                .required(false),
        )
        .get_matches();
    let listen_port = value_t!(matches, "port", u16).unwrap_or_else(|e| e.exit());
    let addr = SocketAddr::from(([127, 0, 0, 1], listen_port));
    if let Some(doh) = matches.value_of("doh") {
        unsafe {
            DOH_ENDPOINT = doh;
        }
    }
    println!("Use dns-over-https: {}", unsafe { DOH_ENDPOINT });

    let http_client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(360))
        .pool_max_idle_per_host(10)
        .build_http();

    let https = HttpsConnector::new();
    let https_client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(360))
        .pool_max_idle_per_host(10)
        .build::<_, hyper::Body>(https);

    let make_service = make_service_fn(move |_| {
        let http_client = http_client.clone();
        let https_client = https_client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy(http_client.clone(), req, https_client.clone())
            }))
        }
    });
    let server = Server::bind(&addr).serve(make_service);

    println!("Listening on http://{}", addr);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn proxy(
    client: HttpClient,
    req: Request<Body>,
    https_client: HttpsClient,
) -> Result<Response<Body>, hyper::Error> {
    // println!("{:?} {:?}", req.method(), req.uri());

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        let uri = req.uri().to_owned();
        tokio::task::spawn(async move {
            match req.into_body().on_upgrade().await {
                Ok(upgraded) => {
                    if let Err(_e) = tunnel(upgraded, &uri, https_client).await {
                        // eprintln!("server io error: {}", e);
                    };
                }
                Err(e) => eprintln!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(Body::empty()))
    } else {
        client.request(req).await
    }
}

async fn split_hello_phrase<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    hostname: &[u8],
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut hello_buf = [0; 1024];
    let n = reader.read(&mut hello_buf).await?;
    let i = find_bytes(&hello_buf, hostname);
    if i.is_none() {
        writer.write(&hello_buf[0..n]).await?;
    } else {
        let middle_hostname = hostname.len() / 2 + i.unwrap();
        writer.write(&hello_buf[0..middle_hostname]).await?;
        writer.write(&hello_buf[middle_hostname..n]).await?;
    }
    Ok(())
}

async fn get_server_connection<'a>(
    uri: &'a http::Uri,
    https_client: HttpsClient,
) -> Option<(TcpStream, &'a [u8])> {
    let auth = uri.authority()?;
    let host = auth.host();
    let host_bytes = host.as_bytes();
    let host_string = host.to_owned();
    let port: u16 = match auth.port() {
        None => 443,
        Some(p) => p.as_u16(),
    };
    // cache
    if let Some(ip) = IP_CACHE.get(&host_string).await {
        let s = TcpStream::connect(SocketAddr::new(ip, port)).await;
        if s.is_ok() {
            return Some((s.unwrap(), host_bytes));
        }
    }
    // if can not connect to cache one, system dns
    let sock_addr = auth.as_str().to_socket_addrs();
    if sock_addr.is_ok() {
        for mut addr in sock_addr.unwrap() {
            addr.set_port(port);
            let s = TcpStream::connect(addr).await;
            if s.is_ok() {
                // save to cache
                IP_CACHE.set(host_string, addr.ip()).await;
                return Some((s.unwrap(), host_bytes));
            }
        }
    }

    // if system dns not resolved, do doh
    let resp = https_client
        .get(
            format!(
                "{}?ct=application/dns-json&type=A&name={}",
                unsafe { DOH_ENDPOINT },
                host_string
            )
            .parse::<http::Uri>()
            .unwrap(),
        )
        .await;
    if resp.is_err() {
        println!("dns-over-https: {}", resp.err()?);
        return None;
    }
    let body = hyper::body::to_bytes(resp.unwrap().body_mut()).await;
    if body.is_err() {
        return None;
    }
    let json = ajson::parse(&std::str::from_utf8(body.unwrap().as_ref()).unwrap())?;
    for ans in &json.get("Answer")?.to_vec() {
        let data = (*ans).get("data");
        if data.is_none() {
            continue;
        }
        let addr = (data.unwrap().as_str(), port)
            .to_socket_addrs()
            .unwrap()
            .next()?;
        let s = TcpStream::connect(addr).await;
        if s.is_ok() {
            // save to cache
            IP_CACHE.set(host_string, addr.ip()).await;
            return Some((s.unwrap(), host_bytes));
        }
    }
    None
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    upgraded: Upgraded,
    uri: &http::Uri,
    https_client: HttpsClient,
) -> std::io::Result<()> {
    // Connect to remote server
    let dns_ret = get_server_connection(uri, https_client).await;
    if dns_ret.is_none() {
        return Ok(());
    }
    let (mut server, hostname) = dns_ret.unwrap();

    // TODO: timeout when visit: .ooklaserver.net, .nflxvideo.net,..
    let set_client_timeout = false;

    // Proxying data
    let amounts = {
        let (mut server_rd, mut server_wr) = server.split();
        let (mut client_rd, mut client_wr) = tokio::io::split(upgraded);

        let server_to_client = tokio::io::copy(&mut server_rd, &mut client_wr);
        split_hello_phrase(&mut client_rd, &mut server_wr, hostname).await?;
        let mut client_rd_timeout = TimeoutReader::new(client_rd);
        if set_client_timeout {
            client_rd_timeout.set_timeout(Some(Duration::from_secs(7)));
        }
        let client_to_server = tokio::io::copy(&mut client_rd_timeout, &mut server_wr);
        try_join(client_to_server, server_to_client).await
    };

    // Print message when done
    match amounts {
        Ok((_from_client, _from_server)) => {
            // println!("client wrote {} bytes and received {} bytes", from_client, from_server);
        }
        Err(_e) => {
            // println!("{} tunnel error: {}", std::str::from_utf8(hostname).unwrap(), e);
        }
    };
    // println!("CLOSED {}", std::str::from_utf8(hostname).unwrap());
    server.shutdown(std::net::Shutdown::Both)?;
    Ok(())
}
