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
}

function end() {
  endTime = performance.now();
  var timeDiff = endTime - startTime; //in ms
  // strip the ms
  timeDiff /= 1000;

  // get seconds
  var seconds = Math.round(timeDiff);
  console.log(seconds + " seconds");
}

const getConstraints = async function(circuit) {
  const r1csUrl = new URL(`${circuit}.r1cs`, `https://localhost:8090/build/${circuit}`).toString();
  const r1cs = await fetch(r1csUrl).then((r) => r.arrayBuffer());
  return r1cs;
}

const getWitnessGenerator = async function(circuit) {
  const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/${circuit}_js/`).toString();
  const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  return wasm;
}

const generateWitnessBytes = async function(inputs) {
  const _snarkjs = import("snarkjs");
  const snarkjs = await _snarkjs;
  const wasm = await getWitnessGenerator(circuit);

  let witnesses = [];
  for(var i =0; i<2; i++) { 
    const witStart = +Date.now();
    let wtns = {type:"mem"};
    await snarkjs.wtns.calculate(inputs[0], new Uint8Array(wasm), wtns);
    const witEnd = +Date.now();
    console.log("witgen time:", witEnd-witStart);
    console.log("witness", wtns);
    witnesses.push({
      val: wtns.data
    });
  };

  return witnesses;
};

// TODO: Migrate this from hardcoded to generated in WASM. 
var inputs = [{
    "key": [49,49,49,49,49,49,49,49,49,49,49,49,49,49,49,49], 
    "iv": [49,49,49,49,49,49,49,49,49,49,49,49], 
    "plainText": [116,101,115,116,104,101,108,108,111,48,48,48,48,48,48,48],
    "aad": [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
    "step_in": [
      [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
      [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0],
      [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]
    ]
}];

// TODO: Configurable identifiers
var circuit = "aes-gcm-fold";
var r1cs = await getConstraints(circuit);
var witnesses = await generateWitnessBytes(inputs);

start();

// TODO: Call this in a web worker so the main thread doesn't hang. 
// Config for local development
const proof = await prover({
  mode: "Origo",
  notary_host: "localhost",
  notary_port: 7443,
  target_method: "GET",
  target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
  target_headers: {},
  target_body: "",
  max_sent_data: 10000,
  max_recv_data: 10000,
  proving: {
    r1cs: r1cs,
    witnesses: witnesses,
  }
});

// const proof = await prover({
//   mode: "TLSN",
//   notary_host: "localhost",
//   notary_port: 7443,
//   target_method: "GET",
//   target_url:
//     "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json", // "https://localhost:8085/health",
//   target_headers: {},
//   target_body: "",
//   websocket_proxy_url: "wss://localhost:7443/v1/tlsnotary/websocket_proxy",
//   max_sent_data: 10000,
//   max_recv_data: 10000,
// });

// Config using notary.pluto.dev
// const proof = await prover({
//   mode: "TLSN",
//   notary_host: "notary.pluto.dev",
//   notary_port: 443,
//   target_method: "GET",
//   target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
//   target_headers: {},
//   target_body: "",
//   websocket_proxy_url: "wss://notary.pluto.dev/v1/tlsnotary/websocket_proxy",
//   max_sent_data: 10000,
//   max_recv_data: 10000,
// });

end();
console.log(proof);

// ./fixture/cets/notary.pub
const pubkey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBv36FI4ZFszJa0DQFJ3wWCXvVLFr\n" +
  "cRzMG5kaTeHGoSzDu6cFqx3uEWYpFGo6C0EOUgf+mEgbktLrXocv5yHzKg==\n" +
  "-----END PUBLIC KEY-----\n";

// const verifyResult = JSON.parse(await verify(proof, pubkey));

// console.log(verifyResult);
