import init, {
  setup_tracing,
  initThreadPool,
  prover,
  verify,
} from "../pkg/client_wasm.js";

const numConcurrency = navigator.hardwareConcurrency;

await init();
setup_tracing("debug,tlsn_extension_rs=debug");
await initThreadPool(numConcurrency);

var startTime, endTime;

function start() {
  startTime = performance.now();
};

function end() {
  endTime = performance.now();
  var timeDiff = endTime - startTime; //in ms 
  // strip the ms 
  timeDiff /= 1000; 
  
  // get seconds 
  var seconds = Math.round(timeDiff);
  console.log(seconds + " seconds");
}

start();

// Config for local development
const proof = await prover(
  {
    notary_host: "localhost",
    notary_port: 7443,
    target_method: "GET",
    target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json", // "https://localhost:8085/health",
    target_headers: {},
    target_body: "",
    // websocket_proxy_url: "wss://ws.alpha4.tlsnotary.pluto.dev",
    websocket_proxy_url: "wss://localhost:7443/v1/tlsnotary/websocket_proxy",
    notarization_session_request: {
      client_type: "Websocket",
      max_sent_data: 10000,
      max_recv_data: 10000,
    }
  }
);

// Config using notary.pluto.dev
// const proof = await prover({
//   notary_host: "notary.pluto.dev",
//   notary_port: 443,
//   target_method: "GET",
//   target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
//   target_headers: {},
//   target_body: "",
//   websocket_proxy_url: "wss://notary.pluto.dev/v1/tlsnotary/websocket_proxy",
//   notarization_session_request: {
//     client_type: "Websocket",
//     max_sent_data: 10000,
//     max_recv_data: 10000,
//   },
// });

end();

console.log(proof);

// TODO verify
// JSON.parse(await verify(JSON.stringify(proof), pubkey));
