use client::{
  circuits,
  config::{self, NotaryMode},
  prover_inner,
};
use wasm_bindgen_test::*;
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_prover_inner() {
  let config_json = include_bytes!("../fixture/client.origo_tcp_local.json");
  let mut config: config::Config = serde_json::from_str(&config_json).unwrap();
  config.set_session_id();

  let proving_params = include_bytes!(circuits::PROVING_PARAMS_1024);

  let proof = prover_inner(config, Some(proving_params)).await.unwrap();

  match proof {
    client::Proof::TLSN(tls_proof) => panic!("expect Origo proof"),
    client::Proof::Origo(origo_proof) => {
      // TODO
      assert_eq!(1, 1)
    },
    client::Proof::TEE() => panic!("expect Origo proof"),
  }
}
