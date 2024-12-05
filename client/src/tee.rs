use core::str;
use std::{collections::HashMap, io};

use jsonwebtoken::{
  decode, decode_header,
  jwk::{AlgorithmParameters, JwkSet},
  Algorithm, DecodingKey, Validation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub fn export_key_material(
  tls_stream: &TlsStream<TcpStream>,
  length: usize,
  label: &[u8],
  context: Option<&[u8]>,
) -> Result<Vec<u8>, io::Error> {
  let rustls_conn = tls_stream.get_ref().1;

  if rustls_conn.is_handshaking() {
    return Err(io::Error::new(io::ErrorKind::Other, "TLS connection is still handshaking"));
  }

  let mut output = vec![0u8; length];
  rustls_conn.export_keying_material(&mut output, label, context).map_err(|err| {
    io::Error::new(io::ErrorKind::Other, format!("Failed to export keying material: {err}"))
  })?;

  Ok(output)
}

pub async fn is_valid_tee_token(
  tee_token: &str,
  key_material: Vec<u8>,
  certs_fingerprint: String,
) -> bool {
  let header = decode_header(tee_token).unwrap();
  let alg = header.alg;
  if alg != Algorithm::RS256 {
    panic!("unsupported JWT alg")
  }

  let mut validation = Validation::new(Algorithm::RS256);
  validation.validate_exp = true;

  // OIDC flow ...
  // https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
  // https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com
  let jwks_request = reqwest::get(
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com",
  )
  .await
  .unwrap();
  let jwks = jwks_request.bytes().await.unwrap();

  let jwks: JwkSet = serde_json::from_str(str::from_utf8(&jwks).unwrap()).unwrap();
  let header = decode_header(tee_token).unwrap();

  let Some(kid) = header.kid else {
    panic!("Token doesn't have a `kid` header field");
  };

  let Some(jwk) = jwks.find(&kid) else {
    panic!("No matching JWK found for the given kid");
  };

  let decoding_key = match &jwk.algorithm {
    AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap(),
    _ => unreachable!("algorithm should be a RSA in this example"),
  };

  let validation = {
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&["https://notary.pluto.xyz"]);
    validation.validate_exp = true;
    validation
  };

  let decoded_token = decode::<JwtPayload>(tee_token, &decoding_key, &validation).unwrap();

  // TODO don't use assert but return boolean success
  assert_eq!(decoded_token.claims.eat_nonce[0], hex::encode(key_material.clone()));
  assert_eq!(decoded_token.claims.eat_nonce[1], certs_fingerprint);

  // PKI flow... (broken)
  // key:
  // https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
  // https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt
  // https://github.com/GoogleCloudPlatform/confidential-space/blob/main/codelabs/health_data_analysis_codelab/src/uwear/workload.go#L84
  //
  // let cert_request = reqwest::get(
  //   "https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt",
  // )
  // .await
  // .unwrap();
  // let cert = cert_request.bytes().await.unwrap();
  // let decoding_key = &DecodingKey::from_rsa_pem(&cert).unwrap();
  // let token_data = decode::<Claims>(tee_token, decoding_key, &validation).unwrap();
  // dbg!(token_data);

  true // TODO
}

pub struct SkipServerVerification;

impl SkipServerVerification {
  pub fn new() -> std::sync::Arc<Self> { std::sync::Arc::new(Self) }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls::Certificate,
    _intermediates: &[rustls::Certificate],
    _server_name: &rustls::ServerName,
    _scts: &mut dyn Iterator<Item = &[u8]>,
    _ocsp_response: &[u8],
    _now: std::time::SystemTime,
  ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
    // TODO check server name
    Ok(rustls::client::ServerCertVerified::assertion())
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtPayload {
  aud:                     String,
  exp:                     u64,
  iat:                     u64,
  iss:                     String,
  nbf:                     u64,
  sub:                     String,
  eat_nonce:               Vec<String>,
  eat_profile:             String,
  secboot:                 bool,
  oemid:                   u32,
  hwmodel:                 String,
  swname:                  String,
  swversion:               Vec<String>,
  attester_tcb:            Vec<String>,
  dbgstat:                 String,
  submods:                 SubModules,
  google_service_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubModules {
  confidential_space: ConfidentialSpace,
  container:          Container,
  gce:                Gce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfidentialSpace {
  monitoring_enabled: MonitoringEnabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitoringEnabled {
  memory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Container {
  image_reference: String,
  image_digest:    String,
  restart_policy:  String,
  image_id:        String,
  env:             HashMap<String, String>,
  args:            Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Gce {
  zone:           String,
  project_id:     String,
  project_number: String,
  instance_name:  String,
  instance_id:    String,
}

// stable_certs_fingerprints returns a sha256 hash over sorted certificates
pub fn stable_certs_fingerprint(certs: &[rustls::Certificate]) -> String {
  let mut sorted_certs: Vec<&rustls::Certificate> = certs.iter().collect();
  sorted_certs.sort_by(|a, b| a.0.cmp(&b.0));

  let mut hasher = Sha256::new();
  for cert in sorted_certs {
    hasher.update(&cert.0);
  }

  hex::encode(hasher.finalize())
}
