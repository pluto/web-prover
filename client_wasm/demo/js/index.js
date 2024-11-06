import init, {
  setup_tracing,
  initThreadPool,
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

const _snarkjs = import("snarkjs");
const snarkjs = await _snarkjs;

const getWitnessGenerator = async function (circuit) {
  const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/target_512b/${circuit}_js/`).toString();
  const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  return wasm;
}

const getSerializedPublicParams = async function (setupFile) {
  const ppUrl = new URL(`${setupFile}.bin`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  return pp;
}

async function generateWitness(circuit, input) {
  const wasm = await getWitnessGenerator(circuit);

  const witStart = +Date.now();
  let wtns = { type: "mem" };
  await snarkjs.wtns.calculate(input, new Uint8Array(wasm), wtns);
  const witEnd = +Date.now();
  console.log("witgen time:", witEnd - witStart);
  console.log("witness", wtns);
  return wtns;
}

const generateWitnessBytes = async function (circuits, inputs) {
  let witnesses = [];

  // AES
  console.log("AES")
  let plaintext_length = inputs[0]["plainText"].length;
  let plaintext = inputs[0]["plainText"];
  for (var i = 0; i < plaintext_length / 16; i++) {
    inputs[0]["plainText"] = plaintext.slice(i * 16, (i + 1) * 16);
    let wtns = await generateWitness(circuits[0], inputs[0]);
    witnesses.push({
      val: wtns.data
    });
  };

  // HTTP lock start line
  console.log("HTTP lock start line");
  let wtns = await generateWitness(circuits[1], inputs[1]);
  witnesses.push({
    val: wtns.data
  });

  console.log("http lock header");
  let wtnsHttp = await generateWitness(circuits[2], inputs[2]);
  witnesses.push({
    val: wtnsHttp.data
  });

  console.log("http body mask");
  let wtnsHttp2 = await generateWitness(circuits[3], inputs[3]);
  witnesses.push({
    val: wtnsHttp2.data
  });

  console.log("json mask object");
  let wtnsJson = await generateWitness(circuits[4], inputs[4]);
  witnesses.push({
    val: wtnsJson.data,
  });

  console.log("json extract value");
  let wtnsFinal = await generateWitness(circuits[6], inputs[6]);
  console.log("wtnsFinal", wtnsFinal);
  witnesses.push({
    val: wtnsFinal.data,
  });

  return witnesses;
};

// TODO: Migrate this from hardcoded to generated in WASM.
const TOTAL_BYTES_ACROSS_NIVC = 512 + 4;
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
let input = Array(50).fill(0).concat(http_response_plaintext);
// let extendedInput = input.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - input.length)).fill(0));
let extendedInput = Array(TOTAL_BYTES_ACROSS_NIVC).fill(0);
let extendedHTTPInput = http_response_plaintext.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - http_response_plaintext.length)).fill(0));

let jsonInput = [123, 13, 10, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32,
  32, 34, 105, 116, 101, 109, 115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116,
  97, 34, 58, 32, 34, 65, 114, 116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32,
  34, 84, 97, 121, 108, 111, 114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125,
  13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125];
let jsonExtendedInput = jsonInput.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - jsonInput.length)).fill(0));

var inputs = [{
  "key": [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49],
  "iv": [49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49],
  "plainText": http_response_plaintext,
  "aad": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "step_in": extendedInput,
}, {
  "beginning": [
    72, 84, 84, 80, 47, 49, 46, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ],
  "beginning_length": [8],
  "middle": [
    50, 48, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
  ],
  "middle_length": [3],
  "final": [
    79, 75, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ],
  "final_length": [2],
  "step_in": extendedHTTPInput,
}, {
  "header": [
    99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ],
  "headerNameLength": [12],
  "value": [
    97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111, 110, 59, 32, 99, 104, 97,
    114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ],
  "headerValueLength": [31],
  "step_in": extendedHTTPInput,
},
{
  "step_in": extendedHTTPInput,
},
{ "key": [100, 97, 116, 97, 0, 0, 0, 0, 0, 0], "keyLen": [4], "step_in": jsonExtendedInput },
// { "key": [105, 116, 101, 109, 115, 0, 0, 0, 0, 0], "keyLen": [5], "step_in": jsonExtendedInput },
{ "index": [0] },
// { "key": [112, 114, 111, 102, 105, 108, 101, 0, 0, 0], "keyLen": [7] },
// { "key": [110, 97, 109, 101, 0, 0, 0, 0, 0, 0], "keyLen": [4] },
{ "step_in": jsonExtendedInput },
];

// TODO: Configurable identifiers
var circuits = ["aes_gctr_nivc_512b", "http_parse_and_lock_start_line_512b", "http_lock_header_512b", "http_body_mask_512b", "json_mask_object_512b", "json_mask_array_index_512b", "json_extract_value_512b"];
// var r1cs = await getConstraints(circuits);
var witnesses = await generateWitnessBytes(circuits, inputs);

console.log("witness", witnesses);

var pp = await getSerializedPublicParams("serialized_setup_aes");

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
    // r1cs: r1cs,
    witnesses: witnesses,
    serialized_pp: pp,
    manifest: {
      "manifestVersion": "1",
      "id": "reddit-user-karma",
      "title": "Total Reddit Karma",
      "description": "Generate a proof that you have a certain amount of karma",
      "prepareUrl": "https://www.reddit.com/login/",
      "request": {
        "method": "GET",
        "version": "HTTP/1.1",
        "url": "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
        "headers": {
          "accept-encoding": "identity"
        },
        "body": {
          "userId": "<% userId %>"
        },
        "vars": {
          "userId": {
            "regex": "[a-z]{,20}+"
          },
          "token": {
            "type": "base64",
            "length": 32
          }
        }
      },
      "response": {
        "status": "200",
        "version": "HTTP/1.1",
        "message": "OK",
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "json": [
            "data",
            "items",
            0
          ],
          "contains": "this_string_exists_in_body"
        }
      }
    },
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
