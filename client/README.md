# Mock client

```shell
cargo run --bin mock_client
```

---

```
Session Proof
- signature.verify(header, notary_pubkey) - via P256
- session_info.verify(header.handshake_summary, root_certs)
    - handshake_decommitment.verify(handshake_summary.handshake_commitment) - verify handshake
        - compares string hash
    - handshake_decommitment.data.verify(root_certs, handshake_summary_time, server_name) - verify server certificate
        - get end cert, and intermediate certs
        - verify end cert is valid for provided server_name and that it chains to at least one of the trusted root certs
            - verify_server_cert in tls-core/src/verify.rs
            - verify TLS 1.2 signature

Body (aka substrings) proof
- substring: merkle tree inclusion proofs
```
