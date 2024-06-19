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
  "https://localhost:8065/health",
  {
    method: "GET",
    headers: {
      Host: "localhost",
      Connection: "close",
    },
    body: "",
    maxTranscriptSize: 16384,
    notaryUrl: "https://localhost:7047",
    websocketProxyUrl: "wss://localhost:8050?target=localhost:8065",
  },
  [],
  []
);
console.log(proof);

// TODO verify
// JSON.parse(await verify(JSON.stringify(proof), pubkey));
