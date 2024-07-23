import init, {
  setup_tracing,
  initThreadPool,
  prover,
  verify
} from "../pkg/client_wasm.js";

const numConcurrency = navigator.hardwareConcurrency;

await init();
setup_tracing("debug,tlsn_extension_rs=debug");
await initThreadPool(numConcurrency);

const proof = await prover(
  {
    notary_host: "localhost",
    notary_port: 7074,
    target_method: "GET",
    target_url: "https://localhost:8085/health",
    target_headers: {},
    target_body: "",
    websocket_proxy_url: "wss://localhost:8050/v1",
    notarization_session_request: {
      client_type: "Websocket",
      max_sent_data: 10000,
      max_recv_data: 10000,
    }
  }
);
console.log(proof);

// TODO verify
// JSON.parse(await verify(JSON.stringify(proof), pubkey));
