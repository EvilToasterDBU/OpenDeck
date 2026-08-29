use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use crypto_box::{
	PublicKey, SalsaBox, SecretKey,
	aead::{Aead, AeadCore, OsRng},
};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;
// Experimental support for the official Elgato Stream Deck Mobile client.
//
// Implements the VSD2 protobuf protocol currently embedded in Stream Deck Mobile.
// The transport is length-delimited protobuf over TCP and a minimal mDNS
// advertisement is emitted for `_elg._tcp.local.`.
//
// This module intentionally exposes the mobile device through OpenDeck's normal
// DeviceInfo/event pipeline, so existing profiles and plugins keep working.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use image::ImageEncoder as _;
use prost::Message;
use qrcodegen::{QrCode, QrCodeEcc};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};

const PORT: u16 = 28198;
const SERVICE_TYPE: &str = "_elg._tcp.local.";
const DEFAULT_COLS: u8 = 5;
const DEFAULT_ROWS: u8 = 3;

static STARTED: OnceLock<()> = OnceLock::new();
static SERVER_KEY: OnceLock<Vec<u8>> = OnceLock::new();
static CLIENTS: LazyLock<RwLock<HashMap<String, ClientHandle>>> = LazyLock::new(|| RwLock::new(HashMap::new()));
#[derive(Clone, serde::Serialize)]
pub struct PendingPairing {
	pub fingerprint: String,
	pub name: String,
	pub peer: String,
	pub approved: bool,
}

static PENDING_PAIRINGS: LazyLock<RwLock<HashMap<String, PendingPairing>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

static CLIENT_PUBLIC_KEYS: LazyLock<RwLock<HashMap<String, Vec<u8>>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

static AUTHENTICATED_CLIENTS: LazyLock<RwLock<std::collections::HashSet<String>>> = LazyLock::new(|| RwLock::new(std::collections::HashSet::new()));

#[derive(Clone)]
struct ClientHandle {
	tx: mpsc::Sender<WsMessage>,
}

fn server_secret_key() -> SecretKey {
	static SERVER_SECRET: OnceLock<SecretKey> = OnceLock::new();

	SERVER_SECRET
		.get_or_init(|| {
			let machine_id = std::fs::read_to_string("/etc/machine-id").unwrap_or_default();

			let mut h = Blake2b512::new();
			h.update(b"OpenDeck Stream Deck Mobile VSD2 server key v1");
			h.update(hostname_string().as_bytes());
			h.update(machine_id.trim().as_bytes());

			let mut bytes = [0u8; 32];
			bytes.copy_from_slice(&h.finalize()[..32]);
			SecretKey::from(bytes)
		})
		.clone()
}

fn server_key() -> &'static [u8] {
	static SERVER_PUBLIC: OnceLock<Vec<u8>> = OnceLock::new();

	SERVER_PUBLIC.get_or_init(|| server_secret_key().public_key().as_bytes().to_vec()).as_slice()
}

fn hostname_string() -> String {
	std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).unwrap_or_else(|_| "OpenDeck".to_owned())
}

fn client_key_id(key: &[u8]) -> String {
	// VSD2 user-facing verification code: first 6 hex characters of
	// BLAKE2b-256(publicKey).
	let mut h = Blake2b::<U32>::new();
	h.update(key);
	hex6(&h.finalize())
}

fn hex6(bytes: &[u8]) -> String {
	bytes.iter().take(3).map(|b| format!("{b:02x}")).collect()
}

fn hex16(bytes: &[u8]) -> String {
	bytes.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

fn local_ipv4() -> Option<Ipv4Addr> {
	let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
	socket.connect((Ipv4Addr::new(8, 8, 8, 8), 53)).ok()?;
	match socket.local_addr().ok()?.ip() {
		IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
		_ => None,
	}
}

fn endpoint_addresses() -> Vec<String> {
	local_ipv4().map(|ip| vec![ip.to_string()]).unwrap_or_else(|| vec!["127.0.0.1".to_owned()])
}

#[derive(serde::Serialize, Clone)]
pub struct PairingCandidate {
	pub name: String,
	pub payload: String,
}

#[derive(serde::Serialize)]
pub struct PairingInfo {
	pub qr_url: String,
	pub qr_data_url: String,
	pub address: String,
	pub legacy_port: u16,
	pub vsd2_port: u16,
	pub token: String,
	pub workstation_id: String,
	pub hostname: String,
	pub public_key_fingerprint: String,
}

fn random_token() -> String {
	use std::time::{SystemTime, UNIX_EPOCH};
	let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
	let mut x = nanos ^ ((std::process::id() as u128) << 64);
	const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
	let mut out = String::with_capacity(27);
	for _ in 0..27 {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		out.push(ALPHABET[(x as usize) % ALPHABET.len()] as char);
	}
	out
}

fn workstation_code() -> String {
	let machine_id = std::fs::read_to_string("/etc/machine-id").ok().map(|v| v.trim().to_owned()).unwrap_or_default();
	let mut h = Blake2b512::new();
	h.update(hostname_string().as_bytes());
	h.update(machine_id.as_bytes());
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&h.finalize()[..16])
}

/// Build the official Stream Deck Mobile QR URL shape observed from Stream Deck Desktop:
/// https://streamdeck.elgato.com/connect/?t=<token>&w=<workstation>&a=<host>:28197&av2=<host>:28198
fn build_qr_data_url(payload: &str) -> Result<String, String> {
	let qr = QrCode::encode_text(payload, QrCodeEcc::Medium).map_err(|e| format!("failed to generate QR code: {e}"))?;
	let size = qr.size();
	let border = 4i32;
	let view = size + border * 2;
	let mut path = String::new();
	for y in 0..size {
		for x in 0..size {
			if qr.get_module(x, y) {
				path.push_str(&format!("M{} {}h1v1h-1z", x + border, y + border));
			}
		}
	}
	let svg = format!(
		r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {view} {view}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##
	);
	Ok(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg.as_bytes())))
}

pub fn pairing_info() -> Result<PairingInfo, String> {
	let address = endpoint_addresses().into_iter().next().unwrap_or_else(|| "127.0.0.1".to_owned());
	let ws = workstation_code();
	let token = random_token();
	let qr_url = format!(
		"https://streamdeck.elgato.com/connect/?t={}&w={}&a={}:{}&av2={}:{}",
		urlencoding::encode(&token),
		urlencoding::encode(&ws),
		address,
		28197,
		address,
		PORT,
	);

	let qr_data_url = build_qr_data_url(&qr_url)?;

	Ok(PairingInfo {
		qr_url,
		qr_data_url,
		address,
		legacy_port: 28197,
		vsd2_port: PORT,
		token,
		workstation_id: ws,
		hostname: hostname_string(),
		public_key_fingerprint: hex16(server_key()),
	})
}

#[tauri::command]
pub fn streamdeck_mobile_pairing_info() -> Result<PairingInfo, String> {
	pairing_info()
}

#[tauri::command]
pub async fn streamdeck_mobile_pending_pairings() -> Result<Vec<PendingPairing>, String> {
	Ok(PENDING_PAIRINGS.read().await.values().cloned().collect())
}

#[tauri::command]
pub async fn streamdeck_mobile_resolve_pairing(fingerprint: String, approve: bool) -> Result<(), String> {
	let mut pending = PENDING_PAIRINGS.write().await;
	if let Some(pairing) = pending.get_mut(&fingerprint) {
		pairing.approved = approve;
		log::info!("[VSD2] desktop pairing decision for {}: approve={}", fingerprint, approve);
		Ok(())
	} else {
		Err(format!("No pending pairing for fingerprint {fingerprint}"))
	}
}

/// Returns true when `device` belongs to this backend.
pub fn is_mobile_device(device: &str) -> bool {
	device.starts_with("sdm-")
}

pub async fn start() {
	if STARTED.set(()).is_err() {
		return;
	}

	tokio::spawn(async {
		if let Err(error) = run_server().await {
			log::error!("Stream Deck Mobile server stopped: {error}");
		}
	});

	tokio::spawn(async {
		run_mdns_announcer().await;
	});
}

async fn run_server() -> anyhow::Result<()> {
	let listener = TcpListener::bind(("0.0.0.0", PORT)).await?;
	log::info!("Stream Deck Mobile VSD2 server listening on 0.0.0.0:{PORT}");

	loop {
		let (stream, peer) = listener.accept().await?;
		tokio::spawn(async move {
			if let Err(error) = handle_client(stream, peer).await {
				log::debug!("Stream Deck Mobile client {peer} disconnected: {error}");
			}
		});
	}
}

async fn handle_client(stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
	let websocket = tokio_tungstenite::accept_async(stream).await?;
	log::info!("[VSD2] WebSocket handshake completed for {peer}");

	let (mut ws_write, mut ws_read) = websocket.split();
	let (ws_tx, mut ws_rx) = mpsc::channel::<WsMessage>(64);

	let writer = tokio::spawn(async move {
		while let Some(message) = ws_rx.recv().await {
			if let Err(error) = ws_write.send(message).await {
				log::error!("[VSD2] WebSocket writer failed: {error}");
				return Err(error);
			}
		}
		Ok::<(), tokio_tungstenite::tungstenite::Error>(())
	});

	// Stream Deck Mobile closes a quiet connection after roughly 10 seconds.
	// The VSD2 socket therefore needs server-side traffic even while the
	// client is waiting for authentication. Use WebSocket Ping frames every
	// 2 seconds; this is independent of the encrypted VSD2 protobuf layer.
	let heartbeat_tx = ws_tx.clone();
	let heartbeat = tokio::spawn(async move {
		let mut interval = tokio::time::interval(Duration::from_secs(2));
		loop {
			interval.tick().await;
			if heartbeat_tx.send(WsMessage::Ping(Vec::new().into())).await.is_err() {
				break;
			}
		}
	});

	let mut device_id: Option<String> = None;
	let mut client_fingerprint: Option<String> = None;
	let mut authenticated = false;

	while let Some(message) = ws_read.next().await {
		match message? {
			WsMessage::Binary(payload) => {
				log::debug!("[VSD2] RX binary frame: {} bytes from {peer}", payload.len());

				let client = match ClientMessage::decode(payload.as_ref()) {
					Ok(client) => client,
					Err(error) => {
						// These 42/44-byte frames are encrypted VSD2 ClientMessage frames.
						// Layout observed from the Mobile client:
						//   24-byte XSalsa20 nonce + ciphertext + 16-byte Poly1305 tag.
						log::debug!("[VSD2] RX encrypted auth frame from {peer}: {} bytes: {error}", payload.len());
						log::debug!("[VSD2] RAW RX {peer}: {}", payload.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));

						if payload.len() >= 24 + 16 {
							if let Some(client_key) = client_fingerprint.as_ref() {
								// Use the actual 32-byte public key received in HelloFromClient.
								let peer_public = match CLIENT_PUBLIC_KEYS.read().await.get(client_key) {
									Some(key) => key.clone(),
									None => {
										log::warn!("[VSD2] no stored public key for {client_key}");
										continue;
									}
								};

								if peer_public.len() == 32 {
									let mut nonce_bytes = [0u8; 24];
									nonce_bytes.copy_from_slice(&payload[..24]);
									let nonce = crypto_box::aead::generic_array::GenericArray::from_slice(&nonce_bytes);

									let peer_pk = PublicKey::from(<[u8; 32]>::try_from(peer_public.as_slice()).unwrap());
									let boxed = SalsaBox::new(&peer_pk, &server_secret_key());

									match boxed.decrypt(nonce, &payload[24..]) {
										Ok(plaintext) => {
											log::info!("[VSD2] decrypted authentication payload from {peer}: {} bytes", plaintext.len());

											match ClientMessage::decode(plaintext.as_slice()) {
												Ok(ClientMessage {
													payload: Some(client_message::Payload::Authenticate(auth)),
												}) => {
													let key_id = client_key.clone();

													// A single Mobile app opens several WebSocket sessions.
													// Once this public key has been approved, subsequent
													// Authenticate messages from that same Mobile identity
													// must not create another desktop prompt.
													if AUTHENTICATED_CLIENTS.read().await.contains(&key_id) {
														log::info!(
															"[VSD2] already-authenticated Mobile client {} requested authentication again (request_id={}); sending OK without another prompt",
															key_id,
															auth.request_id
														);

														let response = ok(auth.request_id).encode_to_vec();
														let nonce = SalsaBox::generate_nonce(&mut OsRng);
														match boxed.encrypt(&nonce, response.as_slice()) {
															Ok(ciphertext) => {
																let mut frame = Vec::with_capacity(24 + ciphertext.len());
																frame.extend_from_slice(nonce.as_slice());
																frame.extend_from_slice(&ciphertext);
																ws_tx.send(WsMessage::Binary(frame.into())).await?;
															}
															Err(error) => {
																log::error!("[VSD2] failed to encrypt repeated authentication OK for {peer}: {error:?}");
															}
														}

														continue;
													}

													{
														let mut pending = PENDING_PAIRINGS.write().await;
														pending.entry(key_id.clone()).or_insert_with(|| PendingPairing {
															fingerprint: key_id.clone(),
															name: "Stream Deck Mobile".to_owned(),
															peer: peer.to_string(),
															approved: false,
														});
													}

													log::info!("[VSD2] decrypted Authenticate from {peer}: request_id={} verification_code={}", auth.request_id, key_id);

													log::info!("[VSD2] desktop approval requested from {peer}: verification_code={}", key_id);

													log::info!("[VSD2] IN_APP_APPROVAL_REQUIRED code={} peer={}", key_id, peer);

													let approved = tokio::time::timeout(Duration::from_secs(120), async {
														loop {
															match PENDING_PAIRINGS.read().await.get(&key_id).cloned() {
																Some(pairing) if pairing.approved => break true,
																Some(_) => {}
																None => break false,
															}
															tokio::time::sleep(Duration::from_millis(100)).await;
														}
													})
													.await
													.unwrap_or(false);

													if approved {
														authenticated = true;
														AUTHENTICATED_CLIENTS.write().await.insert(key_id.clone());

														PENDING_PAIRINGS.write().await.remove(&key_id);

														log::info!(
															"[VSD2] Mobile identity {} is now TRUSTED; future HelloFromClient replies will use clientNeedsAuthentication=false",
															key_id
														);

														let response = ok(auth.request_id).encode_to_vec();
														let nonce = SalsaBox::generate_nonce(&mut OsRng);
														match boxed.encrypt(&nonce, response.as_slice()) {
															Ok(ciphertext) => {
																let mut frame = Vec::with_capacity(24 + ciphertext.len());
																frame.extend_from_slice(nonce.as_slice());
																frame.extend_from_slice(&ciphertext);
																let frame_len = frame.len();
																let frame_prefix = frame.iter().take(24).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");

																ws_tx.send(WsMessage::Binary(frame.into())).await?;
																log::info!(
																	"[VSD2] encrypted authentication OK queued to {peer}: request_id={} frame_len={} nonce_prefix={}",
																	auth.request_id,
																	frame_len,
																	frame_prefix
																);
																log::info!("[VSD2] waiting for next ClientMessage after authentication on {peer}");
															}
															Err(_) => log::error!("[VSD2] failed to encrypt authentication OK for {peer}"),
														}
														PENDING_PAIRINGS.write().await.remove(&key_id);
													} else {
														let response = error_response(auth.request_id, ErrorCode::AuthenticationRejected, "Desktop did not approve this Stream Deck Mobile pairing")
															.encode_to_vec();
														let nonce = SalsaBox::generate_nonce(&mut OsRng);
														if let Ok(ciphertext) = boxed.encrypt(&nonce, response.as_slice()) {
															let mut frame = Vec::with_capacity(24 + ciphertext.len());
															frame.extend_from_slice(nonce.as_slice());
															frame.extend_from_slice(&ciphertext);
															ws_tx.send(WsMessage::Binary(frame.into())).await?;
														}
														PENDING_PAIRINGS.write().await.remove(&key_id);
													}
												}
												Ok(ClientMessage {
													payload: Some(client_message::Payload::CancelAuthenticate(cancel)),
												}) => {
													log::info!("[VSD2] decrypted CancelAuthenticate from {peer}: request_id={}", cancel.request_id);

													let response = error_response(cancel.request_id, ErrorCode::Cancelled, "Authentication cancelled by client").encode_to_vec();

													let nonce = SalsaBox::generate_nonce(&mut OsRng);
													match boxed.encrypt(&nonce, response.as_slice()) {
														Ok(ciphertext) => {
															let mut frame = Vec::with_capacity(24 + ciphertext.len());
															frame.extend_from_slice(nonce.as_slice());
															frame.extend_from_slice(&ciphertext);
															ws_tx.send(WsMessage::Binary(frame.into())).await?;
															log::info!("[VSD2] encrypted Cancelled response sent to {peer}: request_id={}", cancel.request_id);
														}
														Err(error) => {
															log::error!("[VSD2] failed to encrypt Cancelled response for {peer}: {error:?}");
														}
													}
												}
												Ok(other) => {
													log::warn!("[VSD2] decrypted non-Authenticate ClientMessage from {peer}: {:?}", other.payload);
												}
												Err(decode_error) => {
													log::warn!("[VSD2] decrypted auth payload is not protobuf from {peer}: {decode_error}");
													log::debug!("[VSD2] decrypted RAW {peer}: {}", plaintext.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
												}
											}
										}
										Err(_) => {
											log::warn!("[VSD2] could not decrypt authentication frame from {peer} with server key");
										}
									}
								}
							}
						}
						continue;
					}
				};

				match client.payload {
					Some(client_message::Payload::Hello(hello)) => {
						let info = hello.client_information.as_ref();

						if let Some(info) = info {
							log::info!(
								"[VSD2] HelloFromClient from {peer}: name={:?}, ua={:?}, protocol={}, model={:?}, os={:?} {:?}",
								info.name,
								info.user_agent,
								info.protocol_version,
								info.device_model,
								info.os_name,
								info.os_version
							);
						}

						if hello.public_key.is_empty() {
							anyhow::bail!("Stream Deck Mobile sent an empty public key");
						}

						let key_id = client_key_id(&hello.public_key);
						let id = format!("sdm-{key_id}");
						device_id = Some(id);
						client_fingerprint = Some(key_id.clone());

						CLIENT_PUBLIC_KEYS.write().await.insert(key_id.clone(), hello.public_key.clone());

						log::debug!("[VSD2] stored Mobile public key for persistent identity {} ({} bytes)", key_id, hello.public_key.len());

						log::info!("[VSD2] Mobile client verification code/device ID: {key_id}");

						let address = endpoint_addresses().into_iter().next().unwrap_or_else(|| "127.0.0.1".to_owned());

						let already_authenticated = AUTHENTICATED_CLIENTS.read().await.contains(&key_id);

						if already_authenticated {
							authenticated = true;
							log::info!("[VSD2] known trusted Mobile {} connected on a new socket; advertising clientNeedsAuthentication=false", key_id);
						}

						// HelloFromServer is the per-connection capability/trust
						// state. A Mobile client that has already been approved
						// must not be forced through Authenticate again simply
						// because it opened a fresh discovery socket.
						let server_hello = HelloFromServer {
							workstation_id: workstation_code(),
							hostname: hostname_string(),
							version: env!("CARGO_PKG_VERSION").to_owned(),
							protocol_version: 2,
							public_key: server_key().to_vec(),
							client_needs_authentication: !already_authenticated,
							os_name: Some(std::env::consts::OS.to_owned()),
							os_version: None,
							endpoints: Some(ServiceEndpoints {
								addresses: vec![address],
								port: PORT as u32,
							}),
						};

						let response = ServerMessage {
							payload: Some(server_message::Payload::Hello(server_hello)),
						};

						let encoded = response.encode_to_vec();
						log::debug!("[VSD2] TX HelloFromServer to {peer}: {} bytes", encoded.len());

						ws_tx.send(WsMessage::Binary(encoded.into())).await?;

						log::info!("[VSD2] HelloFromServer sent to {peer}; waiting for Mobile auth request");
					}

					Some(client_message::Payload::Authenticate(auth)) => {
						let key_id = client_fingerprint.clone().ok_or_else(|| anyhow::anyhow!("Authenticate received before Hello"))?;

						// THIS is the exact point where desktop pairing becomes
						// relevant. Discovery/Hello never creates a prompt.
						{
							let mut pending = PENDING_PAIRINGS.write().await;
							pending.insert(
								key_id.clone(),
								PendingPairing {
									fingerprint: key_id.clone(),
									name: "Stream Deck Mobile".to_owned(),
									peer: peer.to_string(),
									approved: false,
								},
							);
						}

						log::info!("[VSD2] Authenticate received from {peer}: request_id={} verification_code={}", auth.request_id, key_id);

						let approved = tokio::time::timeout(Duration::from_secs(60), async {
							loop {
								match PENDING_PAIRINGS.read().await.get(&key_id).cloned() {
									Some(pairing) if pairing.approved => break true,
									Some(_) => {}
									None => break false,
								}

								tokio::time::sleep(Duration::from_millis(100)).await;
							}
						})
						.await
						.unwrap_or(false);

						if !approved {
							let response = error_response(auth.request_id, ErrorCode::AuthenticationRejected, "Desktop did not approve this Stream Deck Mobile pairing");

							ws_tx.send(WsMessage::Binary(response.encode_to_vec().into())).await?;

							PENDING_PAIRINGS.write().await.remove(&key_id);

							log::info!("[VSD2] authentication rejected/timed out for {peer}: {key_id}");
							continue;
						}

						authenticated = true;

						let response = ok(auth.request_id);
						ws_tx.send(WsMessage::Binary(response.encode_to_vec().into())).await?;

						PENDING_PAIRINGS.write().await.remove(&key_id);

						log::info!("[VSD2] Authenticate accepted from {peer}: request_id={}", auth.request_id);
					}

					Some(client_message::Payload::CancelAuthenticate(cancel)) => {
						log::info!("[VSD2] CancelAuthenticate from {peer}: request_id={}", cancel.request_id);

						if let Some(key_id) = client_fingerprint.as_deref() {
							PENDING_PAIRINGS.write().await.remove(key_id);
						}

						let response = error_response(cancel.request_id, ErrorCode::Cancelled, "Authentication cancelled by client");

						ws_tx.send(WsMessage::Binary(response.encode_to_vec().into())).await?;
					}

					Some(client_message::Payload::ClientCapabilities(cap)) => {
						log::info!("[VSD2] ClientCapabilities from {peer}: is_user_pro={}", cap.is_user_pro);
					}

					Some(client_message::Payload::CreateVirtualDevice(create)) => {
						let id = device_id.clone().unwrap_or_else(|| format!("sdm-{}", peer.ip()));

						let keypad = create.keypad_config.clone().unwrap_or_else(|| KeypadConfig {
							supported_icon_image_formats: vec![ImageFormat::Png as i32],
							icon_size: Some(Size { width: 96, height: 96 }),
							pressed_icon_size: Some(Size { width: 96, height: 96 }),
							high_dpi: true,
							overscale: true,
							layout_crop: Some(Size {
								width: DEFAULT_COLS as u32,
								height: DEFAULT_ROWS as u32,
							}),
							enable_context_api: true,
						});

						let (rows, columns) = keypad
							.layout_crop
							.as_ref()
							.map(|size| (size.height.clamp(1, 255) as u8, size.width.clamp(1, 255) as u8))
							.unwrap_or((DEFAULT_ROWS, DEFAULT_COLS));

						log::info!(
							"[VSD2] CreateVirtualDevice from {peer}: request_id={} name={:?} layout={}x{} auth={} device={}",
							create.request_id,
							create.name,
							rows,
							columns,
							authenticated,
							id
						);

						register_open_deck_device(&id, &create.name, (rows, columns)).await?;

						CLIENTS.write().await.insert(id.clone(), ClientHandle { tx: ws_tx.clone() });

						let response = ServerMessage {
							payload: Some(server_message::Payload::VirtualDeviceOpened(VirtualDeviceOpened {
								request_id: create.request_id,
								device: Some(VirtualDevice {
									id: id.clone(),
									name: create.name.clone(),
								}),
							})),
						};

						ws_tx.send(WsMessage::Binary(response.encode_to_vec().into())).await?;

						send_context(&ws_tx, &keypad).await?;

						log::info!("[VSD2] virtual device ready: {} ({}x{})", id, rows, columns);
					}

					Some(client_message::Payload::OpenVirtualDevice(open)) => {
						let (rows, columns) = open
							.keypad_config
							.as_ref()
							.and_then(|cfg| cfg.layout_crop.as_ref())
							.map(|size| (size.height.clamp(1, 255) as u8, size.width.clamp(1, 255) as u8))
							.unwrap_or((DEFAULT_ROWS, DEFAULT_COLS));

						log::info!(
							"[VSD2] OpenVirtualDevice from {peer}: request_id={} device_id={} layout={}x{}",
							open.request_id,
							open.device_id,
							rows,
							columns
						);

						if !crate::shared::DEVICES.contains_key(&open.device_id) {
							register_open_deck_device(&open.device_id, "Stream Deck Mobile", (rows, columns)).await?;
						}

						device_id = Some(open.device_id.clone());

						CLIENTS.write().await.insert(open.device_id.clone(), ClientHandle { tx: ws_tx.clone() });

						let response = ServerMessage {
							payload: Some(server_message::Payload::VirtualDeviceOpened(VirtualDeviceOpened {
								request_id: open.request_id,
								device: Some(VirtualDevice {
									id: open.device_id.clone(),
									name: "Stream Deck Mobile".to_owned(),
								}),
							})),
						};

						ws_tx.send(WsMessage::Binary(response.encode_to_vec().into())).await?;

						if let Some(cfg) = open.keypad_config.as_ref() {
							send_context(&ws_tx, cfg).await?;
						}
					}

					Some(client_message::Payload::DeleteVirtualDevice(delete)) => {
						log::info!("[VSD2] DeleteVirtualDevice from {peer}: request_id={}", delete.request_id);

						if let Some(id) = device_id.as_ref() {
							CLIENTS.write().await.remove(id);
							deregister_open_deck_device(id).await;
						}

						let response = ok(delete.request_id);
						ws_tx.send(WsMessage::Binary(response.encode_to_vec().into())).await?;
					}

					Some(client_message::Payload::UpdateKeypadConfig(update)) => {
						log::info!(
							"[VSD2] UpdateKeypadConfig from {peer}: icon_size={:?} pressed_icon_size={:?} layout_crop={:?}",
							update.icon_size.as_ref().map(|s| (s.width, s.height)),
							update.pressed_icon_size.as_ref().map(|s| (s.width, s.height)),
							update.layout_crop.as_ref().map(|s| (s.width, s.height))
						);
					}

					Some(client_message::Payload::KeyPress(key)) => {
						if let Some(id) = device_id.as_ref() {
							log::info!("[VSD2] KeyPress from {peer}: device={} index={} pressed={}", id, key.index, key.pressed);
						}
					}

					Some(client_message::Payload::NextPage(_)) => {
						log::info!("[VSD2] NextPage from {peer}");
					}
					Some(client_message::Payload::PreviousPage(_)) => {
						log::info!("[VSD2] PreviousPage from {peer}");
					}
					Some(client_message::Payload::PageByIndex(page)) => {
						log::info!("[VSD2] PageByIndex from {peer}: index={}", page.index);
					}
					Some(client_message::Payload::AssignShortcut(assign)) => {
						log::info!(
							"[VSD2] AssignShortcut from {peer}: profile={:?} shortcut={:?} index={}",
							assign.profile_id,
							assign.shortcut_id,
							assign.index
						);
					}
					Some(client_message::Payload::RemoveShortcut(remove)) => {
						log::info!("[VSD2] RemoveShortcut from {peer}: request_id={} shortcut={:?}", remove.request_id, remove.shortcut_id);
					}
					Some(client_message::Payload::TriggerShortcut(trigger)) => {
						log::info!("[VSD2] TriggerShortcut from {peer}: device_id={:?} shortcut={:?}", trigger.device_id, trigger.shortcut_id);
					}
					None => log::warn!("[VSD2] empty ClientMessage from {peer}"),
				}
			}

			WsMessage::Ping(payload) => {
				ws_tx.send(WsMessage::Pong(payload)).await?;
			}

			WsMessage::Close(frame) => {
				log::info!("[VSD2] RX close from {peer}: {:?}", frame);
				break;
			}

			WsMessage::Pong(_) | WsMessage::Text(_) | WsMessage::Frame(_) => {}
		}
	}

	if let Some(key_id) = client_fingerprint.as_ref() {
		// Stream Deck Mobile uses multiple short-lived WebSockets. The
		// encrypted authentication frame may arrive on a later socket, so
		// keep the public key by persistent Mobile fingerprint.
		log::debug!("[VSD2] preserving Mobile public-key identity {} after socket disconnect", key_id);
	}

	if let Some(id) = device_id {
		CLIENTS.write().await.remove(&id);
		log::info!("[VSD2] detached device {id} from {peer}");
	}

	drop(ws_tx);
	heartbeat.abort();
	let _ = heartbeat.await;
	let _ = writer.await;

	log::info!("[VSD2] WebSocket client {peer} disconnected");
	Ok(())
}

fn ok(request_id: u32) -> ServerMessage {
	ServerMessage {
		payload: Some(server_message::Payload::Ok(Ok { request_id })),
	}
}

fn error_response(request_id: u32, code: ErrorCode, reason: &str) -> ServerMessage {
	ServerMessage {
		payload: Some(server_message::Payload::Error(Error {
			request_id,
			code: code as i32,
			reason: Some(reason.to_owned()),
		})),
	}
}

async fn register_open_deck_device(device_id: &str, name: &str, (rows, columns): (u8, u8)) -> anyhow::Result<()> {
	if crate::shared::DEVICES.contains_key(device_id) {
		return Ok(());
	}
	crate::events::inbound::devices::register_device(
		"",
		crate::events::inbound::PayloadEvent {
			payload: crate::shared::DeviceInfo {
				id: device_id.to_owned(),
				plugin: String::new(),
				name: name.to_owned(),
				rows,
				columns,
				encoders: 0,
				touchpoints: 0,
				infobars: 0,
				r#type: 3,
			},
		},
	)
	.await?;
	Ok(())
}

async fn deregister_open_deck_device(device_id: &str) {
	let _ = crate::events::inbound::devices::deregister_device("", crate::events::inbound::PayloadEvent { payload: device_id.to_owned() }).await;
}

async fn send_context(tx: &mpsc::Sender<WsMessage>, keypad: &KeypadConfig) -> anyhow::Result<()> {
	let (rows, columns) = keypad
		.layout_crop
		.as_ref()
		.map(|size| (size.height.clamp(1, 255) as u8, size.width.clamp(1, 255) as u8))
		.unwrap_or((DEFAULT_ROWS, DEFAULT_COLS));

	let actions = (0..(rows as u32 * columns as u32))
		.map(|index| Action {
			index,
			title: String::new(),
			name: String::new(),
			category: String::new(),
			shortcut_id: None,
		})
		.collect();

	let message = ServerMessage {
		payload: Some(server_message::Payload::Context(Context {
			profile_id: "opendeck-mobile-profile".to_owned(),
			total_pages: 1,
			current_page: 0,
			actions,
		})),
	};

	tx.send(WsMessage::Binary(message.encode_to_vec().into())).await?;
	Ok(())
}

/// Push an OpenDeck image to a connected Mobile client. Returns true when handled.
pub async fn update_image(device_id: &str, position: u8, data_url: Option<&str>) -> anyhow::Result<bool> {
	if !is_mobile_device(device_id) {
		return Ok(false);
	}
	let client = CLIENTS.read().await.get(device_id).cloned();
	let Some(client) = client else {
		return Ok(true);
	};

	let image = if let Some(data_url) = data_url {
		let Some((_, encoded)) = data_url.split_once(',') else {
			return Ok(true);
		};
		let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
		let img = image::load_from_memory(&bytes)?;
		let rgba = img.to_rgba8();
		let (width, height) = rgba.dimensions();
		let mut out = Vec::with_capacity((width * height * 4) as usize);
		image::codecs::png::PngEncoder::new(&mut out).write_image(&rgba, width, height, image::ExtendedColorType::Rgba8)?;
		Image {
			format: ImageFormat::Png as i32,
			r#type: ImageType::Transparent as i32,
			size: Some(Size { width, height }),
			row_bytes: width * 4,
			image: out,
		}
	} else {
		empty_png()?
	};

	let message = ServerMessage {
		payload: Some(server_message::Payload::Icon(Icon {
			index: position as u32,
			image: Some(image),
		})),
	};
	client.tx.send(WsMessage::Binary(message.encode_to_vec().into())).await?;
	Ok(true)
}

pub async fn clear_screen(device_id: &str) -> bool {
	if !is_mobile_device(device_id) {
		return false;
	}
	let client = CLIENTS.read().await.get(device_id).cloned();
	let Some(client) = client else {
		return true;
	};

	let blank = empty_png().ok();
	let count = crate::shared::DEVICES
		.get(device_id)
		.map(|device| device.rows as u32 * device.columns as u32)
		.unwrap_or(DEFAULT_ROWS as u32 * DEFAULT_COLS as u32);

	for index in 0..count {
		if let Some(image) = blank.clone() {
			let message = ServerMessage {
				payload: Some(server_message::Payload::Icon(Icon { index, image: Some(image) })),
			};
			let _ = client.tx.send(WsMessage::Binary(message.encode_to_vec().into())).await;
		}
	}
	true
}

fn empty_png() -> anyhow::Result<Image> {
	let rgba = image::RgbaImage::from_pixel(2, 2, image::Rgba([0, 0, 0, 0]));
	let (width, height) = rgba.dimensions();
	let mut out = Vec::new();
	image::codecs::png::PngEncoder::new(&mut out).write_image(&rgba, width, height, image::ExtendedColorType::Rgba8)?;
	Ok(Image {
		format: ImageFormat::Png as i32,
		r#type: ImageType::Transparent as i32,
		size: Some(Size { width, height }),
		row_bytes: width * 4,
		image: out,
	})
}

async fn run_mdns_announcer() {
	let Some(ip) = local_ipv4() else {
		log::warn!("Stream Deck Mobile mDNS advertisement disabled: no local IPv4 route found");
		return;
	};

	let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
		Ok(socket) => socket,
		Err(error) => {
			log::warn!("Failed to bind mDNS advertiser: {error}");
			return;
		}
	};
	let _ = socket.set_multicast_ttl_v4(255);

	let instance = format!("OpenDeck-{}", workstation_code());
	let host = format!("opendeck-{}.local.", hex6(server_key()));
	let service = format!("{}.{}", instance, SERVICE_TYPE);

	log::info!(
		"[VSD2] mDNS advertising ONE service: instance={} service={} host={} id={} port={}",
		instance,
		service,
		host,
		workstation_code(),
		PORT
	);

	let hostname = hostname_string();
	for legacy_instance in [format!("OpenDeck {}", hostname), format!("OpenDeck-{}", hostname), "OpenDeck".to_owned()] {
		if legacy_instance == instance {
			continue;
		}
		let legacy_service = format!("{}.{}", legacy_instance, SERVICE_TYPE);
		let goodbye = build_mdns_goodbye(&legacy_service, &host, ip, PORT);
		for _ in 0..3 {
			let _ = socket.send_to(&goodbye, (Ipv4Addr::new(224, 0, 0, 251), 5353));
		}
	}

	let packet = build_mdns_response(&service, &host, &instance, ip, PORT);
	log::debug!("[VSD2] mDNS current PTR target = {}; no additional service instances are generated by this process", service);
	let _ = socket.send_to(&packet, (Ipv4Addr::new(224, 0, 0, 251), 5353));
	loop {
		let packet = build_mdns_response(&service, &host, &instance, ip, PORT);
		let _ = socket.send_to(&packet, (Ipv4Addr::new(224, 0, 0, 251), 5353));
		tokio::time::sleep(Duration::from_secs(10)).await;
	}
}

fn dns_name(name: &str, out: &mut Vec<u8>) {
	for label in name.trim_end_matches('.').split('.') {
		out.push(label.len() as u8);
		out.extend_from_slice(label.as_bytes());
	}
	out.push(0);
}

fn build_mdns_goodbye(service: &str, host: &str, _ip: Ipv4Addr, port: u16) -> Vec<u8> {
	let mut out = Vec::with_capacity(512);
	out.extend_from_slice(&0u16.to_be_bytes());
	out.extend_from_slice(&0x8400u16.to_be_bytes());
	out.extend_from_slice(&0u16.to_be_bytes());
	out.extend_from_slice(&4u16.to_be_bytes());
	out.extend_from_slice(&0u16.to_be_bytes());
	out.extend_from_slice(&0u16.to_be_bytes());

	// PTR
	dns_name(SERVICE_TYPE, &mut out);
	out.extend_from_slice(&12u16.to_be_bytes());
	out.extend_from_slice(&1u16.to_be_bytes());
	out.extend_from_slice(&0u32.to_be_bytes());
	let mut ptr = Vec::new();
	dns_name(service, &mut ptr);
	out.extend_from_slice(&(ptr.len() as u16).to_be_bytes());
	out.extend_from_slice(&ptr);

	// SRV
	dns_name(service, &mut out);
	out.extend_from_slice(&33u16.to_be_bytes());
	out.extend_from_slice(&0x8001u16.to_be_bytes());
	out.extend_from_slice(&0u32.to_be_bytes());
	let mut srv = Vec::new();
	srv.extend_from_slice(&0u16.to_be_bytes());
	srv.extend_from_slice(&0u16.to_be_bytes());
	srv.extend_from_slice(&port.to_be_bytes());
	dns_name(host, &mut srv);
	out.extend_from_slice(&(srv.len() as u16).to_be_bytes());
	out.extend_from_slice(&srv);

	// TXT (empty goodbye record).
	dns_name(service, &mut out);
	out.extend_from_slice(&16u16.to_be_bytes());
	out.extend_from_slice(&0x8001u16.to_be_bytes());
	out.extend_from_slice(&0u32.to_be_bytes());
	out.extend_from_slice(&1u16.to_be_bytes());
	out.push(0);

	// A goodbye.
	dns_name(host, &mut out);
	out.extend_from_slice(&1u16.to_be_bytes());
	out.extend_from_slice(&0x8001u16.to_be_bytes());
	out.extend_from_slice(&0u32.to_be_bytes());
	out.extend_from_slice(&4u16.to_be_bytes());
	out.extend_from_slice(&[0, 0, 0, 0]);

	out
}

fn build_mdns_response(service: &str, host: &str, instance: &str, ip: Ipv4Addr, port: u16) -> Vec<u8> {
	let mut out = Vec::with_capacity(512);
	out.extend_from_slice(&0u16.to_be_bytes());
	out.extend_from_slice(&0x8400u16.to_be_bytes());
	out.extend_from_slice(&0u16.to_be_bytes());
	out.extend_from_slice(&4u16.to_be_bytes());
	out.extend_from_slice(&0u16.to_be_bytes());
	out.extend_from_slice(&0u16.to_be_bytes());

	// PTR: _elg._tcp.local -> <instance>._elg._tcp.local
	dns_name(SERVICE_TYPE, &mut out);
	out.extend_from_slice(&12u16.to_be_bytes());
	out.extend_from_slice(&1u16.to_be_bytes());
	out.extend_from_slice(&30u32.to_be_bytes());
	let mut ptr = Vec::new();
	dns_name(service, &mut ptr);
	out.extend_from_slice(&(ptr.len() as u16).to_be_bytes());
	out.extend_from_slice(&ptr);

	// SRV: <instance>._elg._tcp.local -> host:28198
	dns_name(service, &mut out);
	out.extend_from_slice(&33u16.to_be_bytes());
	out.extend_from_slice(&0x8001u16.to_be_bytes());
	out.extend_from_slice(&30u32.to_be_bytes());
	let mut srv = Vec::new();
	srv.extend_from_slice(&0u16.to_be_bytes()); // priority
	srv.extend_from_slice(&0u16.to_be_bytes()); // weight
	srv.extend_from_slice(&port.to_be_bytes());
	dns_name(host, &mut srv);
	out.extend_from_slice(&(srv.len() as u16).to_be_bytes());
	out.extend_from_slice(&srv);

	// TXT: stable workstation identity + user-visible name.
	dns_name(service, &mut out);
	out.extend_from_slice(&16u16.to_be_bytes());
	out.extend_from_slice(&0x8001u16.to_be_bytes());
	out.extend_from_slice(&30u32.to_be_bytes());

	let txt1 = format!("id={}", workstation_code());
	let txt2 = "name=OpenDeck";
	let txt_len = 1 + txt1.len() + 1 + txt2.len();
	out.extend_from_slice(&(txt_len as u16).to_be_bytes());
	out.push(txt1.len() as u8);
	out.extend_from_slice(txt1.as_bytes());
	out.push(txt2.len() as u8);
	out.extend_from_slice(txt2.as_bytes());

	// A record.
	dns_name(host, &mut out);
	out.extend_from_slice(&1u16.to_be_bytes());
	out.extend_from_slice(&0x8001u16.to_be_bytes());
	out.extend_from_slice(&30u32.to_be_bytes());
	out.extend_from_slice(&4u16.to_be_bytes());
	out.extend_from_slice(&ip.octets());

	debug_assert!(service.starts_with(instance));

	out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum ImageFormat {
	Lzf = 0,
	Lzfse = 1,
	Lz4 = 2,
	Bmp = 3,
	Jpg = 4,
	Png = 5,
	Invalid = 100,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum ImageType {
	Opaque = 0,
	Transparent = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum ErrorCode {
	DeviceNotFound = 0,
	DeviceNameAlreadyTaken = 1,
	ResourceLimitReached = 2,
	AuthenticationRejected = 3,
	Cancelled = 4,
	InvalidState = 5,
}

#[derive(Clone, PartialEq, Message)]
struct Size {
	#[prost(uint32, tag = "1")]
	width: u32,
	#[prost(uint32, tag = "2")]
	height: u32,
}

#[derive(Clone, PartialEq, Message)]
struct Image {
	#[prost(enumeration = "ImageFormat", tag = "1")]
	format: i32,
	#[prost(enumeration = "ImageType", tag = "2")]
	r#type: i32,
	#[prost(message, optional, tag = "3")]
	size: Option<Size>,
	#[prost(uint32, tag = "4")]
	row_bytes: u32,
	#[prost(bytes = "vec", tag = "5")]
	image: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct ClientInformation {
	#[prost(string, tag = "1")]
	name: String,
	#[prost(string, tag = "2")]
	user_agent: String,
	#[prost(uint32, tag = "3")]
	protocol_version: u32,
	#[prost(string, optional, tag = "4")]
	device_model: Option<String>,
	#[prost(string, optional, tag = "5")]
	os_name: Option<String>,
	#[prost(string, optional, tag = "6")]
	os_version: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct HelloFromClient {
	#[prost(bytes = "vec", tag = "1")]
	public_key: Vec<u8>,
	#[prost(message, optional, tag = "2")]
	client_information: Option<ClientInformation>,
}

#[derive(Clone, PartialEq, Message)]
struct Authenticate {
	#[prost(uint32, tag = "1")]
	request_id: u32,
}
#[derive(Clone, PartialEq, Message)]
struct CancelAuthenticate {
	#[prost(uint32, tag = "1")]
	request_id: u32,
}

#[derive(Clone, PartialEq, Message)]
struct KeypadConfig {
	#[prost(enumeration = "ImageFormat", repeated, tag = "1")]
	supported_icon_image_formats: Vec<i32>,
	#[prost(message, optional, tag = "2")]
	icon_size: Option<Size>,
	#[prost(message, optional, tag = "3")]
	pressed_icon_size: Option<Size>,
	#[prost(bool, tag = "4")]
	high_dpi: bool,
	#[prost(bool, tag = "5")]
	overscale: bool,
	#[prost(message, optional, tag = "6")]
	layout_crop: Option<Size>,
	#[prost(bool, tag = "7")]
	enable_context_api: bool,
}

#[derive(Clone, PartialEq, Message)]
struct UpdateKeypadConfig {
	#[prost(message, optional, tag = "1")]
	icon_size: Option<Size>,
	#[prost(message, optional, tag = "2")]
	pressed_icon_size: Option<Size>,
	#[prost(bool, optional, tag = "3")]
	high_dpi: Option<bool>,
	#[prost(message, optional, tag = "4")]
	layout_crop: Option<Size>,
}

#[derive(Clone, PartialEq, Message)]
struct Error {
	#[prost(uint32, tag = "1")]
	request_id: u32,
	#[prost(enumeration = "ErrorCode", tag = "2")]
	code: i32,
	#[prost(string, optional, tag = "3")]
	reason: Option<String>,
}
#[derive(Clone, PartialEq, Message)]
struct Ok {
	#[prost(uint32, tag = "1")]
	request_id: u32,
}

#[derive(Clone, PartialEq, Message)]
struct VirtualDevice {
	#[prost(string, tag = "1")]
	id: String,
	#[prost(string, tag = "2")]
	name: String,
}
#[derive(Clone, PartialEq, Message)]
struct CreateVirtualDevice {
	#[prost(uint32, tag = "1")]
	request_id: u32,
	#[prost(string, tag = "2")]
	name: String,
	#[prost(message, optional, tag = "3")]
	keypad_config: Option<KeypadConfig>,
	#[prost(bool, tag = "4")]
	skip_uniqueness_of_name_validation: bool,
}
#[derive(Clone, PartialEq, Message)]
struct OpenVirtualDevice {
	#[prost(uint32, tag = "1")]
	request_id: u32,
	#[prost(string, tag = "2")]
	device_id: String,
	#[prost(message, optional, tag = "3")]
	keypad_config: Option<KeypadConfig>,
}
#[derive(Clone, PartialEq, Message)]
struct DeleteVirtualDevice {
	#[prost(uint32, tag = "1")]
	request_id: u32,
}
#[derive(Clone, PartialEq, Message)]
struct VirtualDeviceOpened {
	#[prost(uint32, tag = "1")]
	request_id: u32,
	#[prost(message, optional, tag = "2")]
	device: Option<VirtualDevice>,
}
#[derive(Clone, PartialEq, Message)]
struct VirtualDeviceList {
	#[prost(message, repeated, tag = "1")]
	devices: Vec<VirtualDevice>,
}

#[derive(Clone, PartialEq, Message)]
struct ServiceEndpoints {
	#[prost(string, repeated, tag = "1")]
	addresses: Vec<String>,
	#[prost(uint32, tag = "2")]
	port: u32,
}
#[derive(Clone, PartialEq, Message)]
struct ClientCapabilities {
	#[prost(bool, tag = "1")]
	is_user_pro: bool,
}

#[derive(Clone, PartialEq, Message)]
struct HelloFromServer {
	#[prost(string, tag = "1")]
	workstation_id: String,
	#[prost(string, tag = "2")]
	hostname: String,
	#[prost(string, tag = "3")]
	version: String,
	#[prost(uint32, tag = "4")]
	protocol_version: u32,
	#[prost(bytes = "vec", tag = "5")]
	public_key: Vec<u8>,
	#[prost(bool, tag = "6")]
	client_needs_authentication: bool,
	#[prost(string, optional, tag = "7")]
	os_name: Option<String>,
	#[prost(string, optional, tag = "8")]
	os_version: Option<String>,
	#[prost(message, optional, tag = "9")]
	endpoints: Option<ServiceEndpoints>,
}

#[derive(Clone, PartialEq, Message)]
struct Icon {
	#[prost(uint32, tag = "1")]
	index: u32,
	#[prost(message, optional, tag = "2")]
	image: Option<Image>,
}
#[derive(Clone, PartialEq, Message)]
struct KeyPress {
	#[prost(uint32, tag = "1")]
	index: u32,
	#[prost(bool, tag = "2")]
	pressed: bool,
}
#[derive(Clone, PartialEq, Message)]
struct NextPage {}
#[derive(Clone, PartialEq, Message)]
struct PreviousPage {}
#[derive(Clone, PartialEq, Message)]
struct PageByIndex {
	#[prost(uint32, tag = "1")]
	index: u32,
}

#[derive(Clone, PartialEq, Message)]
struct Action {
	#[prost(uint32, tag = "1")]
	index: u32,
	#[prost(string, tag = "2")]
	title: String,
	#[prost(string, tag = "3")]
	name: String,
	#[prost(string, tag = "4")]
	category: String,
	#[prost(string, optional, tag = "5")]
	shortcut_id: Option<String>,
}
#[derive(Clone, PartialEq, Message)]
struct Context {
	#[prost(string, tag = "1")]
	profile_id: String,
	#[prost(uint32, tag = "2")]
	total_pages: u32,
	#[prost(uint32, tag = "3")]
	current_page: u32,
	#[prost(message, repeated, tag = "4")]
	actions: Vec<Action>,
}

#[derive(Clone, PartialEq, Message)]
struct AssignShortcut {
	#[prost(string, tag = "1")]
	profile_id: String,
	#[prost(string, tag = "2")]
	shortcut_id: String,
	#[prost(uint32, tag = "3")]
	index: u32,
}
#[derive(Clone, PartialEq, Message)]
struct RemoveShortcut {
	#[prost(uint32, tag = "1")]
	request_id: u32,
	#[prost(string, tag = "2")]
	shortcut_id: String,
}
#[derive(Clone, PartialEq, Message)]
struct TriggerShortcut {
	#[prost(string, tag = "1")]
	device_id: String,
	#[prost(string, tag = "2")]
	shortcut_id: String,
}

#[derive(Clone, PartialEq, Message)]
struct ServerMessage {
	#[prost(oneof = "server_message::Payload", tags = "1,2,10,20,21,30,31,40")]
	payload: Option<server_message::Payload>,
}
mod server_message {
	use super::*;
	#[derive(Clone, PartialEq, prost::Oneof)]
	pub enum Payload {
		#[prost(message, tag = "1")]
		Error(Error),
		#[prost(message, tag = "2")]
		Ok(Ok),
		#[prost(message, tag = "10")]
		Hello(HelloFromServer),
		#[prost(message, tag = "20")]
		VirtualDeviceList(VirtualDeviceList),
		#[prost(message, tag = "21")]
		VirtualDeviceOpened(VirtualDeviceOpened),
		#[prost(message, tag = "30")]
		Context(Context),
		#[prost(message, tag = "31")]
		ContextUpdate(ContextUpdate),
		#[prost(message, tag = "40")]
		Icon(Icon),
	}
}

#[derive(Clone, PartialEq, Message)]
struct ContextUpdate {
	#[prost(string, tag = "1")]
	profile_id: String,
	#[prost(message, repeated, tag = "2")]
	replace: Vec<Action>,
	#[prost(uint32, repeated, tag = "3")]
	remove: Vec<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct ClientMessage {
	#[prost(oneof = "client_message::Payload", tags = "1,2,3,10,11,12,20,21,22,23,30,31,32,33,100")]
	payload: Option<client_message::Payload>,
}
mod client_message {
	use super::*;
	#[derive(Clone, PartialEq, prost::Oneof)]
	pub enum Payload {
		#[prost(message, tag = "1")]
		Hello(HelloFromClient),
		#[prost(message, tag = "2")]
		Authenticate(Authenticate),
		#[prost(message, tag = "3")]
		CancelAuthenticate(CancelAuthenticate),
		#[prost(message, tag = "10")]
		CreateVirtualDevice(CreateVirtualDevice),
		#[prost(message, tag = "11")]
		OpenVirtualDevice(OpenVirtualDevice),
		#[prost(message, tag = "12")]
		DeleteVirtualDevice(DeleteVirtualDevice),
		#[prost(message, tag = "20")]
		KeyPress(KeyPress),
		#[prost(message, tag = "21")]
		NextPage(NextPage),
		#[prost(message, tag = "22")]
		PreviousPage(PreviousPage),
		#[prost(message, tag = "23")]
		PageByIndex(PageByIndex),
		#[prost(message, tag = "30")]
		UpdateKeypadConfig(UpdateKeypadConfig),
		#[prost(message, tag = "31")]
		AssignShortcut(AssignShortcut),
		#[prost(message, tag = "32")]
		RemoveShortcut(RemoveShortcut),
		#[prost(message, tag = "33")]
		TriggerShortcut(TriggerShortcut),
		#[prost(message, tag = "100")]
		ClientCapabilities(ClientCapabilities),
	}
}
