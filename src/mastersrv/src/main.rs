use arrayvec::ArrayString;
use arrayvec::ArrayVec;
use clap::Arg;
use clap::Command;
use rand::random;
use serde::Deserialize;
use serde::Serialize;
use serde_json as json;
use sha2::Digest;
use sha2::Sha512_256 as SecureHash;
use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map;
use std::ffi::OsStr;
use std::io::Write;
use std::io;
use std::mem;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::panic;
use std::path::Path;
use std::process;
use std::str;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use tokio::fs::File;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::time;
use url::Url;
use warp::Filter;

use crate::addr::Addr;
use crate::addr::Protocol;
use crate::locations::Location;
use crate::locations::Locations;

// Naming convention: Always use the abbreviation `addr` except in user-facing
// (e.g. serialized) identifiers.
mod addr;
mod locations;

type ShortString = ArrayString<64>;

// TODO: make it compile on Windows

#[derive(Debug, Deserialize)]
struct Register {
    address: Url,
    secret: ShortString,
    connless_request_token: Option<ShortString>,
    challenge_token: Option<ShortString>,
    info_serial: i64,
    info: json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
enum RegisterResponse {
    Success(RegisterResponseCommon),
    NeedChallenge(RegisterResponseCommon),
    Error(RegisterError)
}

#[derive(Debug, Serialize)]
struct RegisterResponseCommon {
    address: Addr,
}

#[derive(Debug, Serialize)]
struct RegisterError {
    message: Cow<'static, str>,
}

impl RegisterError {
    fn new(s: String) -> RegisterError {
        RegisterError {
            message: Cow::Owned(s),
        }
    }
}

/// Time in milliseconds since the epoch of the timekeeper.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Timestamp(i64);

impl Timestamp {
    fn minus_seconds(self, seconds: u64) -> Timestamp {
        Timestamp(self.0 - seconds.checked_mul(1_000).unwrap() as i64)
    }
    fn difference_added(self, other: Timestamp, base: Timestamp) -> Timestamp {
        Timestamp(self.0 + (other.0 - base.0))
    }
}

#[derive(Clone, Copy)]
struct Timekeeper {
    instant: Instant,
    system: SystemTime,
}

impl Timekeeper {
    fn new() -> Timekeeper {
        Timekeeper {
            instant: Instant::now(),
            system: SystemTime::now(),
        }
    }
    fn now(&self) -> Timestamp {
        Timestamp(self.instant.elapsed().as_millis() as i64)
    }
    fn from_system_time(&self, system: SystemTime) -> Timestamp {
        let difference = if let Ok(d) = system.duration_since(self.system) {
            d.as_millis() as i64
        } else {
            -(self.system.duration_since(system).unwrap().as_millis() as i64)
        };
        Timestamp(difference)
    }
}

#[derive(Debug, Serialize)]
struct SerializedServers<'a> {
    pub servers: Vec<SerializedServer<'a>>,
}

impl<'a> SerializedServers<'a> {
    fn new() -> SerializedServers<'a> {
        SerializedServers {
            servers: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SerializedServer<'a> {
    pub addresses: &'a [Addr],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    pub info: &'a json::value::RawValue,
}

impl<'a> SerializedServer<'a> {
    fn new(server: &'a Server, location: Option<Location>) -> SerializedServer<'a> {
        SerializedServer {
            addresses: &server.addresses,
            location,
            info: &server.info,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct DumpServer<'a> {
    pub info_serial: i64,
    pub info: Cow<'a, json::value::RawValue>,
}

impl<'a> From<&'a Server> for DumpServer<'a> {
    fn from(server: &'a Server) -> DumpServer<'a> {
        DumpServer {
            info_serial: server.info_serial,
            info: Cow::Borrowed(&server.info),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Dump<'a> {
    pub now: Timestamp,
    pub addresses: Cow<'a, HashMap<Addr, AddrInfo>>,
    pub servers: HashMap<Cow<'a, str>, DumpServer<'a>>,
}

impl<'a> Dump<'a> {
    fn new(now: Timestamp, servers: &'a Servers) -> Dump<'a> {
        Dump {
            now,
            addresses: Cow::Borrowed(&servers.addresses),
            servers: servers.servers.iter().map(|(secret, server)| {
                (Cow::Borrowed(&**secret), DumpServer::from(server))
            }).collect(),
        }
    }
    fn fixup_timestamps(&mut self, new_now: Timestamp) {
        let self_now = self.now;
        let translate_timestamp = |ts| new_now.difference_added(ts, self_now);
        self.now = translate_timestamp(self.now);
        for a_info in self.addresses.to_mut().values_mut() {
            a_info.ping_time = translate_timestamp(a_info.ping_time);
        }
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum EntryKind {
    Backcompat,
    Mastersrv,
}

#[derive(Clone, Deserialize, Serialize)]
struct AddrInfo {
    kind: EntryKind,
    ping_time: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<Location>,
    secret: ShortString,
}

struct Challenge {
    current: ShortString,
    prev: ShortString,
}

impl Challenge {
    fn is_valid(&self, challenge: &str) -> bool {
        challenge == &self.current || challenge == &self.prev
    }
    fn current(&self) -> &str {
        &self.current
    }
}

struct Challenger {
    seed: [u8; 16],
    prev_seed: [u8; 16],
}

impl Challenger {
    fn new() -> Challenger {
        Challenger {
            seed: random(),
            prev_seed: random(),
        }
    }
    fn reseed(&mut self) {
        self.prev_seed = mem::replace(&mut self.seed, random());
    }
    fn for_addr(&self, addr: &Addr) -> Challenge {
        fn hash(seed: &[u8], addr: &[u8]) -> ShortString {
            let mut hash = SecureHash::new();
            hash.update(addr);
            hash.update(seed);
            let mut buf = [0; 64];
            let len = base64::encode_config_slice(&hash.finalize()[..16], base64::STANDARD, &mut buf);
            ShortString::from(str::from_utf8(&buf[..len]).unwrap()).unwrap()
        }
        let mut buf: ArrayVec<u8, 128> = ArrayVec::new();
        write!(&mut buf, "{}", addr).unwrap();
        Challenge {
            current: hash(&self.seed, &buf),
            prev: hash(&self.prev_seed, &buf),
        }
    }
}

struct Shared<'a> {
    challenger: &'a Mutex<Challenger>,
    locations: &'a Locations,
    servers: &'a Mutex<Servers>,
    socket: &'a Arc<tokio::net::UdpSocket>,
    timekeeper: Timekeeper,
}

impl<'a> Shared<'a> {
    fn challenge_for_addr(&self, addr: &Addr) -> Challenge {
        self.challenger.lock().unwrap_or_else(|poison| poison.into_inner())
            .for_addr(addr)
    }
    fn lock_servers(&'a self) -> sync::MutexGuard<'a, Servers> {
        self.servers.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Maintains a mapping from server addresses to server info. 
///
/// Also maintains a mapping from addresses to corresponding server addresses.
#[derive(Clone, Deserialize, Serialize)]
struct Servers {
    pub addresses: HashMap<Addr, AddrInfo>,
    pub servers: HashMap<ShortString, Server>,
}

impl Servers {
    fn new() -> Servers {
        Servers {
            addresses: HashMap::new(),
            servers: HashMap::new(),
        }
    }
    fn add(
        &mut self,
        addr: Addr,
        a_info: AddrInfo,
        info_serial: i64,
        info: Cow<'_, json::value::RawValue>,
    ) {
        let insert_addr;
        let secret = a_info.secret.clone();
        match self.addresses.entry(addr) {
            hash_map::Entry::Vacant(v) => {
                v.insert(a_info);
                insert_addr = true;
            },
            hash_map::Entry::Occupied(mut o) => {
                if a_info.kind < o.get().kind {
                    // Don't replace masterserver entries with stuff from backcompat.
                    return;
                }
                if a_info.ping_time < o.get().ping_time {
                    // Don't replace address info with older one.
                    return;
                }
                let old = o.insert(a_info);
                insert_addr = old.secret != secret;
                if insert_addr {
                    let server = self.servers.get_mut(&old.secret).unwrap();
                    server.addresses.retain(|&a| a != addr);
                    if server.addresses.is_empty() {
                        assert!(self.servers.remove(&old.secret).is_some());
                    }
                }
            },
        }
        match self.servers.entry(secret) {
            hash_map::Entry::Vacant(v) => {
                assert!(insert_addr);
                v.insert(Server {
                    addresses: vec![addr],
                    info_serial,
                    info: info.into_owned(),
                });
            },
            hash_map::Entry::Occupied(mut o) => {
                let mut server = &mut o.get_mut();
                if insert_addr {
                    server.addresses.push(addr);
                    server.addresses.sort_unstable();
                }
                if info_serial > server.info_serial {
                    server.info_serial = info_serial;
                    server.info = info.into_owned();
                }
            },
        }
    }
    fn prune_before(&mut self, time: Timestamp) {
        let mut remove = Vec::new();
        for (&addr, a_info) in &self.addresses {
            if a_info.ping_time < time {
                remove.push(addr);
            }
        }
        for addr in remove {
            let secret = self.addresses.remove(&addr).unwrap().secret;
            let server = self.servers.get_mut(&secret).unwrap();
            server.addresses.retain(|&a| a != addr);
            if server.addresses.is_empty() {
                assert!(self.servers.remove(&secret).is_some());
            }
        }
    }
    fn merge(&mut self, other: &Dump) {
        for (&addr, a_info) in &*other.addresses {
            let server = &other.servers[&*a_info.secret];
            self.add(
                addr,
                a_info.clone(),
                server.info_serial,
                Cow::Borrowed(&server.info),
            );
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Server {
    pub addresses: Vec<Addr>,
    pub info_serial: i64,
    pub info: Box<json::value::RawValue>,
}

impl From<&'static str> for RegisterError {
    fn from(s: &'static str) -> RegisterError {
        RegisterError {
            message: Cow::Borrowed(s),
        }
    }
}

async fn handle_periodic_reseed(challenger: Arc<Mutex<Challenger>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        challenger.lock().unwrap_or_else(|poison| poison.into_inner()).reseed();
    }
}

async fn read_dump_dir(path: &Path, timekeeper: Timekeeper) -> Vec<Dump<'static>> {
    // TODO: unwrap
    let mut dir_entries = fs::read_dir(path).await.unwrap();
    let mut dumps = Vec::new();
    let mut buffer = Vec::new();
    while let Some(entry) = dir_entries.next_entry().await.unwrap() {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let timestamp = timekeeper.from_system_time(fs::metadata(&path).await.unwrap().modified().unwrap());
        buffer.clear();
        File::open(&path).await.unwrap().read_to_end(&mut buffer).await.unwrap();
        let mut dump: Dump = json::from_slice(&buffer).unwrap();
        dump.fixup_timestamps(timestamp);
        dumps.push((path, dump));
    }
    dumps.sort_unstable_by(|(path1, _), (path2, _)| path1.cmp(path2));
    dumps.into_iter().map(|(_, dump)| dump).collect()
}

async fn overwrite_atomically<P, Q>(filename: P, temp_filename: Q, content: &[u8])
    -> io::Result<()>
    where P: AsRef<Path>,
          Q: AsRef<Path>,
{
    async fn impl_(filename: &Path, temp_filename: &Path, content: &[u8]) -> io::Result<()> {
        fs::write(temp_filename, content).await?;
        fs::rename(temp_filename, filename).await?;
        Ok(())
    }
    impl_(filename.as_ref(), temp_filename.as_ref(), content).await
}

async fn handle_periodic_writeout(
    servers: Arc<Mutex<Servers>>,
    dumps_dir: Option<String>,
    dump_filename: Option<String>,
    addresses_filename: Option<String>,
    servers_filename: String,
    timekeeper: Timekeeper,
) {
    let mut prev: Option<String> = None;
    let mut printed_ellipsis = false;

    let dump_filename = dump_filename.map(|f| {
        let tmp = format!("{}.tmp.{}", f, process::id());
        (f, tmp)
    });
    let addresses_filename = addresses_filename.map(|f| {
        let tmp = format!("{}.tmp.{}", f, process::id());
        (f, tmp)
    });
    let servers_filename_temp = &format!("{}.tmp.{}", servers_filename, process::id());

    let start = Instant::now();
    let mut iteration = 0;

    loop {
        let now = timekeeper.now();
        let mut servers = {
            let mut servers = servers.lock().unwrap_or_else(|poison| poison.into_inner());
            servers.prune_before(now.minus_seconds(30));
            servers.clone()
        };
        if let Some((filename, filename_temp)) = &dump_filename {
            let json = json::to_string(&Dump::new(now, &servers)).unwrap();
            overwrite_atomically(filename, filename_temp, json.as_bytes()).await.unwrap();
        }
        {
            let other_dumps = match &dumps_dir {
                Some(dir) => read_dump_dir(Path::new(dir), timekeeper).await,
                None => Vec::new(),
            };
            if let Some((filename, filename_temp)) = &addresses_filename {
                let mut non_backcompat_addrs: Vec<Addr> = Vec::new();
                non_backcompat_addrs.extend(servers.addresses.keys());
                let oldest = now.minus_seconds(30);
                for other_dump in &other_dumps {
                    non_backcompat_addrs.extend(other_dump.addresses.iter()
                        .filter(|(_, a_info)| a_info.kind != EntryKind::Backcompat && a_info.ping_time >= oldest)
                        .map(|(addr, _)| addr)
                    );
                }
                non_backcompat_addrs.sort_unstable();
                non_backcompat_addrs.dedup();
                let json = json::to_string(&non_backcompat_addrs).unwrap();
                overwrite_atomically(filename, filename_temp, json.as_bytes()).await.unwrap();
            }
            for other_dump in &other_dumps {
                servers.merge(other_dump);
            }
            drop(other_dumps);
            let json = {
                let mut serialized = SerializedServers::new();
                servers.prune_before(now.minus_seconds(30));
                serialized.servers.extend(servers.servers.values().map(|s| {
                    // Get the location of the first registered address. Since
                    // the addresses are kept sorted, this is stable.
                    let location = s.addresses
                        .iter()
                        .filter_map(|addr| servers.addresses[addr].location)
                        .next();
                    SerializedServer::new(s, location)
                }));
                serialized.servers.sort_by_key(|s| s.addresses);
                json::to_string(&serialized).unwrap()
            };
            overwrite_atomically(&servers_filename, servers_filename_temp, json.as_bytes()).await.unwrap();
            if prev.as_ref().map(|p| p.get(16..) != json.get(16..)).unwrap_or(true) {
                println!("{}", json);
                prev = Some(json);
                printed_ellipsis = false;
            } else if !printed_ellipsis {
                println!("...");
                printed_ellipsis = true;
            }
        }
        let elapsed = start.elapsed();
        if elapsed.as_secs() <= iteration {
            let remaining_ns = 1_000_000_000 - elapsed.subsec_nanos();
            time::sleep(Duration::new(0, remaining_ns)).await;
            iteration += 1;
        } else {
            iteration = elapsed.as_secs();
        }
    }
}

async fn send_challenge(
    connless_request_token_7: Option<[u8; 4]>,
    socket: Arc<tokio::net::UdpSocket>,
    target: SocketAddr,
    secret: ShortString,
    addr: Addr,
    challenge: ShortString,
) {
    let mut packet = Vec::with_capacity(128);
    if let Some(t) = connless_request_token_7 {
        packet.extend_from_slice(b"\x21");
        packet.extend_from_slice(&t);
        packet.extend_from_slice(b"\xff\xff\xff\xff\xff\xff\xff\xffchal");
    } else {
        packet.extend_from_slice(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffchal");
    }
    packet.extend_from_slice(secret.as_bytes());
    packet.push(0);
    write!(&mut packet, "{}", addr).unwrap();
    packet.push(0);
    packet.extend_from_slice(challenge.as_bytes());
    packet.push(0);
    socket.send_to(&packet, target).await.unwrap();
}

fn handle_register(
    shared: Shared,
    remote_addr: IpAddr,
    register: Register,
) -> Result<RegisterResponse, RegisterError> {
    let protocol: Protocol = register.address.scheme().parse()
        .map_err(|_| "register address must start with one of tw-0.5+udp://, tw-0.6+udp://, tw-0.7+udp://")?;

    let connless_request_token_7 = match protocol {
        Protocol::V5 => None,
        Protocol::V6 => None,
        Protocol::V7 => {
            let token_hex = register.connless_request_token.as_ref().ok_or_else(|| {
                "registering with tw-0.7+udp:// requires field \"connless_request_token\""
            })?;
            let mut token = [0; 4];
            hex::decode_to_slice(token_hex.as_bytes(), &mut token).map_err(|e| RegisterError::new(format!("invalid hex in connless_request_token: {}", e)))?;
            Some(token)
        },
    };
    if register.address.host_str() != Some("connecting-address.invalid") {
        return Err("register address must have domain connecting-address.invalid".into());
    }
    let port = if let Some(p) = register.address.port() {
        p
    } else {
        return Err("register address must specify port".into());
    };

    let addr = Addr { ip: remote_addr, port, protocol };
    let challenge = shared.challenge_for_addr(&addr);

    let correct_challenge = register.challenge_token.as_ref()
        .map(|ct| challenge.is_valid(ct))
        .unwrap_or(false);
    let should_send_challenge = register.challenge_token.as_ref()
        .map(|ct| ct != challenge.current())
        .unwrap_or(true);

    let common = RegisterResponseCommon { address: addr };
    let result = if correct_challenge {
        let info = register.info.as_object().ok_or("register info must be an object")?;

        // Normalize the JSON to strip any spaces etc.
        let raw_info = json::to_string(&info).unwrap();
        let raw_info = json::value::RawValue::from_string(raw_info).unwrap();

        shared.lock_servers().add(
            addr,
            AddrInfo {
                kind: EntryKind::Mastersrv,
                ping_time: shared.timekeeper.now(),
                location: shared.locations.lookup(addr.ip),
                secret: register.secret.clone(),
            },
            register.info_serial,
            Cow::Owned(raw_info),
        );

        RegisterResponse::Success(common)
    } else {
        RegisterResponse::NeedChallenge(common)
    };

    if should_send_challenge {
        println!("sending challenge to {}", addr);
        tokio::spawn(send_challenge(
            connless_request_token_7,
            shared.socket.clone(),
            SocketAddr::new(remote_addr, port),
            register.secret,
            addr,
            challenge.current,
        ));
    }

    Ok(result)
}

#[derive(Clone)]
struct AssertUnwindSafe<T>(pub T);
impl<T> panic::UnwindSafe for AssertUnwindSafe<T> {}
impl<T> panic::RefUnwindSafe for AssertUnwindSafe<T> {}

// TODO: put active part masterservers on a different domain?
#[tokio::main]
async fn main() {
    env_logger::init();

    let mut command = Command::new("mastersrv")
        .about("Collects game server info via an HTTP endpoint and aggregates them.")
        .arg(Arg::new("listen")
            .long("listen")
            .value_name("ADDRESS")
            .default_value("[::]:8080")
            .help("Listen address for the HTTP endpoint.")
        )
        .arg(Arg::new("connecting-ip-header")
            .long("connecting-ip-header")
            .value_name("HEADER")
            .help("HTTP header to use to determine the client IP address.")
        )
        .arg(Arg::new("locations")
            .long("locations")
            .value_name("LOCATIONS")
            .help("IP to continent locations database filename (CSV file with network,continent_code header).")
        )
        .arg(Arg::new("write-addresses")
            .long("write-addresses")
            .value_name("FILENAME")
            .help("Dump all new-style addresses to a file each second.")
        )
        .arg(Arg::new("write-dump")
            .long("write-dump")
            .value_name("DUMP")
            .help("Dump the internal state to a JSON file each second.")
        )
        .arg(Arg::new("read-dump-dir")
            .long("read-dump-dir")
            .takes_value(true)
            .value_name("DUMP_DIR")
            .help("Read dumps from other mastersrv instances from the specified directory (looking only at *.json files).")
        )
        .arg(Arg::new("out")
            .long("out")
            .value_name("OUT")
            .default_value("servers.json")
            .help("Output file for the aggregated server list in a DDNet 15.5+ compatible format.")
        );

    if cfg!(unix) {
        command = command
            .arg(Arg::new("listen-unix")
                .long("listen-unix")
                .value_name("PATH")
                .requires("connecting-ip-header")
                .conflicts_with("listen")
                .help("Listen on the specified Unix domain socket.")
            );
    }

    let matches = command.get_matches();

    let listen_address: SocketAddr = matches.value_of_t_or_exit("listen");
    let connecting_ip_header = matches.value_of("connecting-ip-header").map(|s| s.to_owned());
    let listen_unix = if cfg!(unix) { matches.value_of("listen-unix") } else { None };

    let challenger = Arc::new(Mutex::new(Challenger::new()));
    let locations = Arc::new(matches.value_of("locations")
        .map(|l| Locations::read(Path::new(&l)))
        .transpose()
        .unwrap()
        .unwrap_or_else(Locations::empty));
    let servers = Arc::new(Mutex::new(Servers::new()));
    let socket = Arc::new(tokio::net::UdpSocket::bind("[::]:0").await.unwrap());
    let socket = AssertUnwindSafe(socket);
    let timekeeper = Timekeeper::new();

    tokio::spawn(handle_periodic_reseed(challenger.clone()));
    tokio::spawn(handle_periodic_writeout(
        servers.clone(),
        matches.value_of("read-dump-dir").map(|s| s.to_owned()),
        matches.value_of("write-dump").map(|s| s.to_owned()),
        matches.value_of("write-addresses").map(|s| s.to_owned()),
        matches.value_of("out").unwrap().to_owned(),
        timekeeper,
    ));

    // TODO: put all fields except the server info into http headers for better
    // HPACK/QPACK compression?
    let register = warp::post()
        .and(warp::path!("ddnet"/"15"/"register"))
        .and(warp::header::headers_cloned())
        .and(warp::addr::remote())
        .and(warp::body::content_length_limit(16 * 1024)) // limit body size to 16 KiB
        .and(warp::body::json())
        .map(move |headers: warp::http::HeaderMap, addr: Option<SocketAddr>, register: Register| {
            let (http_status, body) = match panic::catch_unwind(|| {
                let shared = Shared {
                    challenger: &challenger,
                    locations: &locations,
                    servers: &servers,
                    socket: &socket.0,
                    timekeeper: timekeeper,
                };
                let mut addr = if let Some(header) = &connecting_ip_header {
                    headers
                        .get(header)
                        .ok_or_else(|| RegisterError::new(format!("missing {} header", header)))?
                        .to_str()
                        .map_err(|_| RegisterError::from("non-ASCII in connecting IP header"))?
                        .parse()
                        .map_err(|e| RegisterError::new(format!("{}", e)))?
                } else {
                    addr.unwrap().ip()
                };
                if let IpAddr::V6(v6) = addr {
                    if let Some(v4) = v6.to_ipv4() {
                        // TODO: switch to `to_ipv4_mapped` in the future.
                        if !v6.is_loopback() {
                            addr = IpAddr::from(v4);
                        }
                    }
                }
                handle_register(shared, addr, register)
            }) {
                Ok(Ok(r)) => (warp::http::StatusCode::OK, r),
                Ok(Err(e)) => (warp::http::StatusCode::BAD_REQUEST, RegisterResponse::Error(e)),
                Err(_) => (warp::http::StatusCode::INTERNAL_SERVER_ERROR, RegisterResponse::Error("unexpected panic".into())),
            };
            // TODO: better error responses when generated by warp
            warp::http::Response::builder()
                .status(http_status)
                .body(json::to_string(&body).unwrap())
        });
    let server = warp::serve(register);

    if let Some(path) = listen_unix {
        #[cfg(unix)]
        {
            use tokio::net::UnixListener;
            use tokio_stream::wrappers::UnixListenerStream;
            let _ = fs::remove_file(path).await;
            let unix_socket = UnixListener::bind(path).unwrap();
            server.run_incoming(UnixListenerStream::new(unix_socket)).await
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            unreachable!();
        }
    } else {
        server.run(listen_address).await
    }
}
