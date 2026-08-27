// A TLS 1.2/1.3 client engine for the IWA, built on rustls and exposed to JS via
// wasm-bindgen. The JS adapter drives it over a Direct Sockets TCPSocket using
// the explicit feed/drain model:
//   recv(ciphertext_from_socket) -> process
//   take_outgoing() -> ciphertext to write to the socket
//   send(app_plaintext) / read() -> app plaintext
//
// Randomness comes from Web Crypto (getrandom "js"); time from the JS clock
// (pki-types "web"). Certificate verification is intentionally disabled (pentest
// tooling against authorised hosts); the peer certificate is exported so the
// caller can derive the `tls-server-end-point` channel binding (RFC 5929).

use std::io::{Read, Write};
use std::sync::Arc;

use wasm_bindgen::prelude::*;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

fn to_js<E: std::fmt::Display>(e: E) -> JsError { JsError::new(&e.to_string()) }

// Accept any certificate — captured for channel binding, not trust.
#[derive(Debug)]
struct NoVerify;
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self, _end: &CertificateDer<'_>, _inter: &[CertificateDer<'_>],
        _name: &ServerName<'_>, _ocsp: &[u8], _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> { Ok(ServerCertVerified::assertion()) }
    fn verify_tls12_signature(&self, _m: &[u8], _c: &CertificateDer<'_>, _d: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn verify_tls13_signature(&self, _m: &[u8], _c: &CertificateDer<'_>, _d: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, ECDSA_NISTP256_SHA256,
             ECDSA_NISTP384_SHA384, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, ED25519]
    }
}

#[wasm_bindgen]
pub struct TlsSession {
    conn: ClientConnection,
    peer_cert: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl TlsSession {
    #[wasm_bindgen(constructor)]
    pub fn new(host: String) -> Result<TlsSession, JsError> {
        let name = ServerName::try_from(host).map_err(to_js)?;
        let provider = Arc::new(rustls_rustcrypto::provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions().map_err(to_js)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let conn = ClientConnection::new(Arc::new(config), name).map_err(to_js)?;
        Ok(TlsSession { conn, peer_cert: None })
    }

    // Feed ciphertext received from the socket; process handshake/app records.
    pub fn recv(&mut self, data: &[u8]) -> Result<(), JsError> {
        let mut rd = data;
        while !rd.is_empty() {
            let n = self.conn.read_tls(&mut rd).map_err(to_js)?;
            if n == 0 { break; }
            self.conn.process_new_packets().map_err(to_js)?;
        }
        if self.peer_cert.is_none() {
            if let Some(c) = self.conn.peer_certificates().and_then(|cs| cs.first()) {
                self.peer_cert = Some(c.as_ref().to_vec());
            }
        }
        Ok(())
    }

    // Ciphertext the engine wants written to the socket (undefined if none).
    pub fn take_outgoing(&mut self) -> Option<Vec<u8>> {
        if !self.conn.wants_write() { return None; }
        let mut buf = Vec::new();
        self.conn.write_tls(&mut buf).ok()?;
        if buf.is_empty() { None } else { Some(buf) }
    }

    // Queue application plaintext (encrypted into the outgoing TLS stream).
    pub fn send(&mut self, data: &[u8]) -> Result<(), JsError> {
        self.conn.writer().write_all(data).map_err(to_js)?;
        Ok(())
    }

    // Decrypted application plaintext, if any (undefined otherwise).
    pub fn read(&mut self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 16384];
        match self.conn.reader().read(&mut buf) {
            Ok(n) if n > 0 => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    pub fn is_handshaking(&self) -> bool { self.conn.is_handshaking() }

    // The peer leaf certificate (DER), for tls-server-end-point channel binding.
    pub fn peer_cert(&self) -> Option<Vec<u8>> { self.peer_cert.clone() }
}
