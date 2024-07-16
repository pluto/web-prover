import init, {
  setup_tracing_web,
  initThreadPool,
  prover,
  verify
} from "../pkg/index.js";

const numConcurrency = navigator.hardwareConcurrency;

await init();
setup_tracing_web("info,tlsn_extension_rs=debug");
await initThreadPool(numConcurrency);

const proof = await prover(
  {
    notary_host: "localhost",
    notary_port: 7074,
    target_method: "GET",
    target_url: "https://localhost:8065/health",
    target_headers: {},
    target_body: "",
    websocket_proxy_url: "wss://localhost:8050",
    notarization_session_request: {
      client_type: "Websocket",
      max_sent_data: 16384,
      max_recv_data: 16384,
    },
    notary_ca_cert_path: "FIXME"
  }
);
console.log(proof);

// TODO verify
// JSON.parse(await verify(JSON.stringify(proof), pubkey));
