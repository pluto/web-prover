use tracing::info;
use wasm_bindgen::prelude::*;

use crate::request_opt::VerifyResult;

use elliptic_curve::pkcs8::DecodePublicKey;
use std::time::Duration;
use tlsn_core::proof::{SessionProof, TlsProof};

#[wasm_bindgen]
pub async fn verify(proof: &str, notary_pubkey_str: &str) -> Result<String, JsValue> {
    let proof: TlsProof = serde_json::from_str(proof)
        .map_err(|e| JsValue::from_str(&format!("Could not deserialize proof: {:?}", e)))?;

    let TlsProof {
        // The session proof establishes the identity of the server and the commitments
        // to the TLS transcript.
        session,
        // The substrings proof proves select portions of the transcript, while redacting
        // anything the Prover chose not to disclose.
        substrings,
    } = proof;

    info!(
        "!@# notary_pubkey {}, {}",
        notary_pubkey_str,
        notary_pubkey_str.len()
    );
    session
        .verify_with_default_cert_verifier(get_notary_pubkey(notary_pubkey_str)?)
        .map_err(|e| JsValue::from_str(&format!("Session verification failed: {:?}", e)))?;

    let SessionProof {
        // The session header that was signed by the Notary is a succinct commitment to the TLS transcript.
        header,
        // This is the server name, checked against the certificate chain shared in the TLS handshake.
        session_info,
        ..
    } = session;

    // The time at which the session was recorded
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(header.time());

    // Verify the substrings proof against the session header.
    //
    // This returns the redacted transcripts
    let (mut sent, mut recv) = substrings
        .verify(&header)
        .map_err(|e| JsValue::from_str(&format!("Could not verify substrings: {:?}", e)))?;

    // Replace the bytes which the Prover chose not to disclose with 'X'
    sent.set_redacted(b'X');
    recv.set_redacted(b'X');

    info!("-------------------------------------------------------------------");
    info!(
        "Successfully verified that the bytes below came from a session with {:?} at {}.",
        session_info.server_name, time
    );
    info!("Note that the bytes which the Prover chose not to disclose are shown as X.");
    info!("Bytes sent:");
    info!(
        "{}",
        String::from_utf8(sent.data().to_vec()).map_err(|e| JsValue::from_str(&format!(
            "Could not convert sent data to string: {:?}",
            e
        )))?
    );
    info!("Bytes received:");
    info!(
        "{}",
        String::from_utf8(recv.data().to_vec()).map_err(|e| JsValue::from_str(&format!(
            "Could not convert recv data to string: {:?}",
            e
        )))?
    );
    info!("-------------------------------------------------------------------");

    let result = VerifyResult {
        server_name: String::from(session_info.server_name.as_str()),
        time: header.time(),
        sent: String::from_utf8(sent.data().to_vec()).map_err(|e| {
            JsValue::from_str(&format!("Could not convert sent data to string: {:?}", e))
        })?,
        recv: String::from_utf8(recv.data().to_vec()).map_err(|e| {
            JsValue::from_str(&format!("Could not convert recv data to string: {:?}", e))
        })?,
    };
    let res = serde_json::to_string_pretty(&result)
        .map_err(|e| JsValue::from_str(&format!("Could not serialize result: {:?}", e)))?;

    Ok(res)
}

#[allow(unused)]
fn print_type_of<T: ?Sized>(_: &T) {
    info!("{}", std::any::type_name::<T>());
}

/// Returns a Notary pubkey trusted by this Verifier
fn get_notary_pubkey(pubkey: &str) -> Result<p256::PublicKey, JsValue> {
    p256::PublicKey::from_public_key_pem(pubkey)
        .map_err(|e| JsValue::from_str(&format!("Could not get notary pubkey: {:?}", e)))
}
