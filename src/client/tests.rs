#[cfg(all(not(target_arch = "wasm32"), not(target_os = "ios"), not(feature = "websocket")))]
#[test]
fn test_prover_examplecom() {
  let notarization_session_request = NotarizationSessionRequest {
    client_type:   ClientType::Tcp,
    max_sent_data: Some(4096),
    max_recv_data: Some(4096),
  };
  let config = Config {
    notary_host: "tlsnotary.pluto.xyz".into(),
    notary_port: 443,
    target_method: "GET".into(),
    target_url: "https://example.com".into(),
    target_headers: Default::default(),
    target_body: "".into(),
    notarization_session_request,
    notary_ca_cert_path: "src/fixture/mock_server/ca-cert.pem".into(),
  };
  let proof = prover(config).unwrap();
  //   assert!(serde.len() > 0);
  //   assert!(proof_str.contains("handshake_summary"));
}

// #[tokio::test]
// async fn test_prover_jsonplaceholder() {
//   let config = Config {
//     notary_host:    "tlsnotary.pluto.xyz".into(),
//     notary_port:    443,
//     target_method:  "GET".into(),
//     target_url:     "https://jsonplaceholder.typicode.com/todos/1".into(),
//     target_headers: HashMap::from([
//       ("Authorization".to_string(), vec![
//         "Bearer 6e539700b0b648946905d70a834877c65a4e5885f5f7d679a8a21b51899ecbe5".to_string(),
//       ]),
//       ("Content-Type".to_string(), vec!["application/json".to_string()]),
//     ]),
//     target_body:    "".into(),
//     max_sent_data:  Some(4096),
//     max_recv_data:  Some(16384),
//   };
//   let proof_str = async_prover(config).await;
//   assert!(proof_str.len() > 0);
//   assert!(proof_str.contains("handshake_summary"));
// }
