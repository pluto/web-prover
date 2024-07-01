pub mod notary;
pub mod routes;
use pki_types::{CertificateDer, PrivateKeyDer};
use std::{fs, io};
use anyhow::Result;


pub fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).collect()
}

pub fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

pub fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

/// Read a PEM-formatted file and return its buffer reader
#[allow(dead_code)]
async fn read_pem_file(file_path: &str) -> Result<io::BufReader<std::fs::File>> {
    let key_file = tokio::fs::File::open(file_path).await?.into_std().await;
    Ok(io::BufReader::new(key_file))
}
