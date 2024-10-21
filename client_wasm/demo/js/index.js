import init, {
  setup_tracing,
  initThreadPool,
  prover,
  verify,
} from "../pkg/client_wasm.js";

const numConcurrency = navigator.hardwareConcurrency;

// Create a WebAssembly.Memory object
const memory = new WebAssembly.Memory({
  initial: 16384, // 256 pages = 16MB
  maximum: 65536, // 1024 pages = 64MB
  shared: true, // Enable shared memory
});

await init(undefined, memory);
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

const getConstraints = async function (circuits) {
  let circuit_r1cs = []
  for (var i = 0; i < circuits.length; i++) {
    let circuit = circuits[i];
    const r1csUrl = new URL(`${circuit}.r1cs`, `https://localhost:8090/build/${circuit}/`).toString();
    const r1cs = await fetch(r1csUrl).then((r) => r.arrayBuffer());
    circuit_r1cs.push(r1cs);
  }

  return circuit_r1cs;
}

const getWitnessGenerator = async function (circuits) {
  let circuit_wasm = []
  for (var i = 0; i < circuits.length; i++) {
    let circuit = circuits[i];
    const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/${circuit}/${circuit}_js/`).toString();
    const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  }
  return circuit_wasm;
}

const getSerializedPublicParams = async function (setupFile) {
  const ppUrl = new URL(`${setupFile}.bin`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  return pp;
}

const generateWitnessBytes = async function (inputs) {
  const _snarkjs = import("snarkjs");
  const snarkjs = await _snarkjs;
  const wasm = await getWitnessGenerator(circuit);

  let witnesses = [];
  for (var i = 0; i < 2; i++) {
    const witStart = +Date.now();
    let wtns = { type: "mem" };
    await snarkjs.wtns.calculate(inputs[0], new Uint8Array(wasm), wtns);
    const witEnd = +Date.now();
    console.log("witgen time:", witEnd - witStart);
    console.log("witness", wtns);
    witnesses.push({
      val: wtns.data
    });
  };

  return witnesses;
};

// TODO: Migrate this from hardcoded to generated in WASM.
const DATA_BYTES = 320;
const MAX_STACK_HEIGHT = 5;
const PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
const TOTAL_BYTES_ACROSS_NIVC = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1) + 1;
let http_response_plaintext = [
  72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101, 110,
  116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106,
  115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 99,
  111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105,
  112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58,
  32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32, 34, 100, 97, 116,
  97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32,
  91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115,
  116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114,
  111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119,
  105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13,
  10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
  10, 32, 32, 32, 125, 13, 10, 125];
let jsonInput = Array(50).fill(0).concat(http_response_plaintext);
let extendedJsonInput = jsonInput.concat(Array(Math.max(0, 4160 - jsonInput.length)).fill(0));

console.log(extendedJsonInput);

var inputs = [{
  // "key": [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49],
  // "iv": [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49],
  // "plainText": [116, 101, 115, 116, 104, 101, 108, 108, 111, 48, 48, 48, 48, 48, 48, 48],
  // "aad": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "beginning": [72, 84, 84, 80, 47, 49, 46, 49],
  "middle": [50, 48, 48],
  "final": [79, 75],
  "step_in": extendedJsonInput,
}];

// TODO: Configurable identifiers
// var circuit = "aes_gcm";
var circuit = ["http_parse_and_lock_start_line", "http_lock_header", "http_body_mask", "json_parse", "json_mask_object", "json_mask_array_index", "extract_value"];
var r1cs = await getConstraints(circuit);
var witnesses = await generateWitnessBytes(inputs);
var pp = await getSerializedPublicParams("serialized_setup_no_aes");

start();

let proverConfig = {
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
    serialized_pp: pp,
  }
};

const proofWorker = new Worker(new URL("./proof.js", import.meta.url), { type: "module" });
console.log("sending message to worker");
proofWorker.postMessage({ proverConfig, memory });

proofWorker.onmessage = (event) => {
  if (event.data.error) {
    console.error("Error from worker:", event.data.error);
  } else {
    console.log("proof generated!", event.data);
  }
}
// TODO: Call this in a web worker so the main thread doesn't hang.
// Config for local development
// const proof = await prover({
//   mode: "Origo",
//   notary_host: "localhost",
//   notary_port: 7443,
//   target_method: "GET",
//   target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
//   target_headers: {},
//   target_body: "",
//   max_sent_data: 10000,
//   max_recv_data: 10000,
//   proving: {
//     r1cs: r1cs,
//     witnesses: witnesses,
//     serialized_pp: pp,
//   }
// });

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
// console.log(proof);

// ./fixture/cets/notary.pub
const pubkey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBv36FI4ZFszJa0DQFJ3wWCXvVLFr\n" +
  "cRzMG5kaTeHGoSzDu6cFqx3uEWYpFGo6C0EOUgf+mEgbktLrXocv5yHzKg==\n" +
  "-----END PUBLIC KEY-----\n";

// const verifyResult = JSON.parse(await verify(proof, pubkey));

// console.log(verifyResult);
