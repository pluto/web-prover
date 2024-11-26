import init, {
  setup_tracing,
  initThreadPool,
  ByteParamsWasm
} from "../pkg/client_wasm.js";
import { poseidon2 } from "poseidon-lite";
import { toByte, computeHttpWitnessBody, computeHttpWitnessHeader, computeHttpWitnessStartline, compute_json_witness, byteArrayToString } from "./witness.js";
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

const getSerializedHashParams = async function (setupFile) {
  const ppUrl = new URL(`${setupFile}.bin`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  console.log("hash_params", pp);
  return pp;
}

const getSerializedCircuitParams = async function (setupFile) {
  const ppUrl = new URL(`${setupFile}.json`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.json());
  console.log("circuit_params", pp);
  return pp;
}

const getByteParams = async function (setupFile, additionalPath) {
  const ppUrl = new URL(`${setupFile}.${additionalPath}`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  console.log("byte_params", pp);
  return pp;
}

async function generateWitness(circuit, input, wasm) {
  const witStart = +Date.now();
  let wtns = { type: "mem" };
  await snarkjs.wtns.calculate(input, new Uint8Array(wasm), wtns);
  const witEnd = +Date.now();
  console.log("witgen time:", witEnd - witStart);
  console.log("witness", wtns);
  return wtns;
}

function DataHasher(input) {
  if (input.length % 16 !== 0) {
    throw new Error("DATA_BYTES must be divisible by 16");
  }

  let hashes = [BigInt(0)];  // Initialize first hash as 0

  for (let i = 0; i < Math.floor(input.length / 16); i++) {
    let packedInput = BigInt(0);

    // Pack 16 bytes into a single number
    for (let j = 0; j < 16; j++) {
      packedInput += BigInt(input[16 * i + j]) * BigInt(2 ** (8 * j));
    }

    // Compute next hash using previous hash and packed input, but if packed input is zero, don't hash it.
    if (packedInput == BigInt(0)) {
      hashes.push(hashes[i]);
    } else {
      hashes.push(poseidon2([hashes[i], packedInput]));
    }
  }

  // Return the last hash
  return hashes[Math.floor(input.length / 16)];
}

const generateWitnessBytesForResponse = async function (circuits, inputs) {
  let witnesses = [];

  let plaintext = inputs[0]["plainText"];
  let extendedHTTPInput = plaintext.concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(0));

  // AES
  console.log("AES");
  let plaintext_length = plaintext.length;
  let cipherText = inputs[0]["cipherText"].concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(0));
  let cached_wasm = {};

  inputs[0]["step_in"] = 0;
  for (var i = 0; i < plaintext_length / 16; i++) {
    inputs[0]["plainText"] = plaintext.slice(i * 16, (i + 1) * 16);
    inputs[0]["cipherText"] = cipherText.slice(i * 16, (i + 1) * 16);
    inputs[0]["ctr"] = [0, 0, 0, i + 1];
    console.log("inputs[0]", inputs[0]);
    if(!(circuits[0] in cached_wasm)) {
      const wasm = await getWitnessGenerator(circuits[0]);
      cached_wasm[circuits[0]] = wasm;
    }
    let wtns = await generateWitness(circuits[0], inputs[0], cached_wasm[circuits[0]]);
    witnesses.push(wtns.data);
    inputs[0]["step_in"] = DataHasher(plaintext.slice(0, (i + 1) * 16));
  };

  // HTTP
  let http_start_line = computeHttpWitnessStartline(extendedHTTPInput);
  let http_header_0 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-type"));
  let http_header_1 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-encoding"));
  let http_body = computeHttpWitnessBody(extendedHTTPInput);

  inputs[1]["start_line_hash"] = DataHasher(http_start_line);
  let http_header_0_hash = DataHasher(http_header_0[1]);
  let http_header_1_hash = DataHasher(http_header_1[1]);
  inputs[1]["header_hashes"] = [http_header_0_hash, http_header_1_hash, 0, 0, 0, 0, 0, 0, 0, 0];
  inputs[1]["body_hash"] = DataHasher(http_body);
  inputs[1]["step_in"] = DataHasher(extendedHTTPInput);
  inputs[1]["data"] = extendedHTTPInput;
  let wtns = await generateWitness(circuits[1], inputs[1], await getWitnessGenerator(circuits[1]));
  witnesses.push(wtns.data);

  console.log("json mask object");
  inputs[2]["data"] = http_body;
  inputs[2]["step_in"] = DataHasher(http_body);
  let json_wasm = await getWitnessGenerator(circuits[2])
  let wtnsJsonKey1 = await generateWitness(circuits[2], inputs[2], json_wasm);
  witnesses.push(wtnsJsonKey1.data);

  console.log("json mask object");
  let jsonWitnessKey1 = compute_json_witness(http_body, byteArrayToString(inputs[2]["key"].slice(0, inputs[2]["keyLen"])));
  inputs[3]["data"] = jsonWitnessKey1;
  inputs[3]["step_in"] = DataHasher(jsonWitnessKey1);
  let wtnsJsonKey2 = await generateWitness(circuits[2], inputs[3], json_wasm);
  witnesses.push(wtnsJsonKey2.data);

  console.log("json mask array");
  let jsonWitnessKey2 = compute_json_witness(jsonWitnessKey1, byteArrayToString(inputs[3]["key"].slice(0, inputs[3]["keyLen"])));
  inputs[4]["data"] = jsonWitnessKey2;
  inputs[4]["step_in"] = DataHasher(jsonWitnessKey2);
  let wtnsJsonKey3 = await generateWitness(circuits[3], inputs[4], await getWitnessGenerator(circuits[3]));
  witnesses.push(wtnsJsonKey3.data);

  console.log("json mask object");
  let jsonWitnessKey3 = compute_json_witness(jsonWitnessKey2, inputs[4]["index"]);
  inputs[5]["data"] = jsonWitnessKey3;
  inputs[5]["step_in"] = DataHasher(jsonWitnessKey3);
  let wtnsJsonKey4 = await generateWitness(circuits[2], inputs[5], json_wasm);
  witnesses.push(wtnsJsonKey4.data);

  console.log("json mask object");
  let jsonWitnessKey4 = compute_json_witness(jsonWitnessKey3, byteArrayToString(inputs[5]["key"].slice(0, inputs[5]["keyLen"])));
  inputs[6]["data"] = jsonWitnessKey4;
  inputs[6]["step_in"] = DataHasher(jsonWitnessKey4);
  let wtnsJsonKey5 = await generateWitness(circuits[2], inputs[6], json_wasm);
  witnesses.push(wtnsJsonKey5.data);

  console.log("json extract value");
  let jsonWitnessKey5 = compute_json_witness(jsonWitnessKey4, byteArrayToString(inputs[6]["key"].slice(0, inputs[6]["keyLen"])));
  inputs[7]["data"] = jsonWitnessKey5
  inputs[7]["step_in"] = DataHasher(jsonWitnessKey5);
  let wtnsFinal = await generateWitness(circuits[4], inputs[7], await getWitnessGenerator(circuits[4]));
  console.log("wtnsFinal", wtnsFinal);
  witnesses.push(wtnsFinal.data);

  return witnesses;
};

const generateWitnessBytesForRequest = async function (circuits, inputs) {
  let witnesses = [];

  let plaintext = inputs[0]["plainText"];
  let extendedHTTPInput = plaintext.concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(0));
  let cached_wasm = {};

  // AES
  console.log("AES");
  let plaintext_length = plaintext.length;
  let cipherText = inputs[0]["cipherText"].concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(0));
  inputs[0]["step_in"] = 0;
  for (var i = 0; i < plaintext_length / 16; i++) {
    inputs[0]["plainText"] = plaintext.slice(i * 16, (i + 1) * 16);
    inputs[0]["cipherText"] = cipherText.slice(i * 16, (i + 1) * 16);
    inputs[0]["ctr"] = [0, 0, 0, i + 1];
    if(!(circuits[0] in cached_wasm)) {
      const wasm = await getWitnessGenerator(circuits[0]);
      cached_wasm[circuits[0]] = wasm;
    }
    let wtns = await generateWitness(circuits[0], inputs[0], cached_wasm[circuits[0]]);
    witnesses.push(wtns.data);
    inputs[0]["step_in"] = DataHasher(plaintext.slice(0, (i + 1) * 16));
  };

  // HTTP
  // TODO: Bring back with update for v5.7
  // 
  // let http_start_line = computeHttpWitnessStartline(extendedHTTPInput);
  // let http_header_0 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-type"));
  // let http_header_1 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-encoding"));
  // let http_body = computeHttpWitnessBody(extendedHTTPInput);

  // inputs[1]["start_line_hash"] = DataHasher(http_start_line);
  // let http_header_0_hash = DataHasher(http_header_0[1]);
  // let http_header_1_hash = DataHasher(http_header_1[1]);
  // // inputs[1]["header_hashes"] = [http_header_0_hash, http_header_1_hash, 0, 0, 0, 0, 0, 0, 0, 0];
  // // inputs[1]["body_hash"] = DataHasher(http_body);
  // inputs[1]["step_in"] = DataHasher(extendedHTTPInput);
  // inputs[1]["data"] = extendedHTTPInput;

  // 
  // TODO: Janky hack to work with my local v5.5 circuits
  let http_start_line_padded = http_start_line.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - http_start_line.length)).fill(0));
  let http_header_0_padded = http_header_0.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - http_header_0.length)).fill(0));
  let http_header_1_padded = http_header_1.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - http_header_1.length)).fill(0));
  let http_body_padded = http_body.concat(Array(Math.max(0, TOTAL_BYTES_ACROSS_NIVC - http_body.length)).fill(0));

  inputs[1]["start_line_hash"] = DataHasher(http_start_line_padded);
  let http_header_0_hash = DataHasher(http_header_0_padded);
  let http_header_1_hash = DataHasher(http_header_1_padded);
  inputs[1]["header_hashes"] = [http_header_0_hash, http_header_1_hash, 0, 0, 0];
  inputs[1]["body_hash"] = DataHasher(http_body_padded);
  inputs[1]["step_in"] = DataHasher(extendedHTTPInput);
  inputs[1]["data"] = extendedHTTPInput;

  let wtns = await generateWitness(circuits[1], inputs[1], await getWitnessGenerator(circuits[1]));
  witnesses.push(wtns.data);

  // console.log("json mask object");
  // inputs[2]["data"] = http_body;
  // inputs[2]["step_in"] = DataHasher(http_body);
  // let wtnsJsonKey1 = await generateWitness(circuits[2], inputs[2]);
  // witnesses.push({
  //   val: wtnsJsonKey1.data,
  // });

  // console.log("json mask object");
  // let jsonWitnessKey1 = compute_json_witness(http_body, byteArrayToString(inputs[2]["key"].slice(0, inputs[2]["keyLen"])));
  // inputs[3]["data"] = jsonWitnessKey1;
  // inputs[3]["step_in"] = DataHasher(jsonWitnessKey1);
  // let wtnsJsonKey2 = await generateWitness(circuits[2], inputs[3]);
  // witnesses.push({
  //   val: wtnsJsonKey2.data,
  // });

  // console.log("json mask array");
  // let jsonWitnessKey2 = compute_json_witness(jsonWitnessKey1, byteArrayToString(inputs[3]["key"].slice(0, inputs[3]["keyLen"])));
  // inputs[4]["data"] = jsonWitnessKey2;
  // inputs[4]["step_in"] = DataHasher(jsonWitnessKey2);
  // let wtnsJsonKey3 = await generateWitness(circuits[3], inputs[4]);
  // witnesses.push({
  //   val: wtnsJsonKey3.data,
  // });

  // console.log("json mask object");
  // let jsonWitnessKey3 = compute_json_witness(jsonWitnessKey2, inputs[4]["index"]);
  // inputs[5]["data"] = jsonWitnessKey3;
  // inputs[5]["step_in"] = DataHasher(jsonWitnessKey3);
  // let wtnsJsonKey4 = await generateWitness(circuits[2], inputs[5]);
  // witnesses.push({
  //   val: wtnsJsonKey4.data,
  // });

  // console.log("json mask object");
  // let jsonWitnessKey4 = compute_json_witness(jsonWitnessKey3, byteArrayToString(inputs[5]["key"].slice(0, inputs[5]["keyLen"])));
  // inputs[6]["data"] = jsonWitnessKey4;
  // inputs[6]["step_in"] = DataHasher(jsonWitnessKey4);
  // let wtnsJsonKey5 = await generateWitness(circuits[2], inputs[6]);
  // witnesses.push({
  //   val: wtnsJsonKey5.data,
  // });

  // console.log("json extract value");
  // let jsonWitnessKey5 = compute_json_witness(jsonWitnessKey4, byteArrayToString(inputs[6]["key"].slice(0, inputs[6]["keyLen"])));
  // inputs[7]["data"] = jsonWitnessKey5
  // inputs[7]["step_in"] = DataHasher(jsonWitnessKey5);
  // let wtnsFinal = await generateWitness(circuits[4], inputs[7]);
  // console.log("wtnsFinal", wtnsFinal);
  // witnesses.push({
  //   val: wtnsFinal.data,
  // });

  return witnesses;
};

const http_start_line = [
  72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0,
];
const http_header_0 = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 111, 110, 116, 101, 110, 116, 45, 116,
  121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115, 111,
  110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const http_header_1 = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  99, 111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122,
  105, 112, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const http_body = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 13, 10, 32, 32, 32, 34,
  100, 97, 116, 97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109,
  115, 34, 58, 32, 91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114,
  116, 105, 115, 116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111,
  114, 32, 83, 119, 105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32,
  32, 32, 93, 13, 10, 32, 32, 32, 125, 13, 10, 125,
];

const TOTAL_BYTES_ACROSS_NIVC = 512;
const AES_PLAINTEXT = [
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

const AES_CIPHER_TEXT = [
  75, 220, 142, 158, 79, 135, 141, 163, 211, 26, 242, 137, 81, 253, 181, 117, 253, 246, 197, 197,
  61, 46, 55, 87, 218, 137, 240, 143, 241, 177, 225, 129, 80, 114, 125, 72, 45, 18, 224, 179, 79,
  231, 153, 198, 163, 252, 197, 219, 233, 46, 202, 120, 99, 253, 76, 9, 70, 11, 200, 218, 228, 251,
  133, 248, 233, 177, 19, 241, 205, 128, 65, 76, 10, 31, 71, 198, 177, 78, 108, 246, 175, 152, 42,
  97, 255, 182, 157, 245, 123, 95, 130, 101, 129, 138, 236, 146, 47, 22, 22, 13, 125, 1, 109, 158,
  189, 131, 44, 43, 203, 118, 79, 181, 86, 33, 235, 186, 75, 20, 7, 147, 102, 75, 90, 222, 255,
  140, 94, 52, 191, 145, 192, 71, 239, 245, 247, 175, 117, 136, 173, 235, 250, 189, 74, 155, 103,
  25, 164, 187, 22, 26, 39, 37, 113, 248, 170, 146, 73, 75, 45, 208, 125, 49, 101, 11, 120, 215,
  93, 160, 14, 147, 129, 181, 150, 59, 167, 197, 230, 122, 77, 245, 247, 215, 136, 98, 1, 180, 213,
  30, 214, 88, 83, 42, 33, 112, 61, 4, 197, 75, 134, 149, 22, 228, 24, 95, 131, 35, 44, 181, 135,
  31, 173, 36, 23, 192, 177, 127, 156, 199, 167, 212, 66, 235, 194, 102, 61, 144, 121, 59, 187,
  179, 212, 34, 117, 47, 96, 3, 169, 73, 204, 88, 36, 48, 158, 220, 237, 198, 180, 105, 7, 188,
  109, 24, 201, 217, 186, 191, 232, 63, 93, 153, 118, 214, 157, 167, 15, 216, 191, 152, 41, 106,
  24, 127, 8, 144, 78, 218, 133, 125, 89, 97, 10, 246, 8, 244, 112, 169, 190, 206, 14, 217, 109,
  147, 130, 61, 214, 237, 143, 77, 14, 14, 70, 56, 94, 97, 207, 214, 106, 249, 37, 7, 186, 95, 174,
  146, 203, 148, 173, 172, 13, 113
];

var inputs = [{
  "key": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "iv": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "plainText": AES_PLAINTEXT,
  "cipherText": AES_CIPHER_TEXT,
  "ctr": [0, 0, 0, 0],
  "aad": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "step_in": 0,
},
{
  "data": AES_PLAINTEXT,
},
  // { "key": [100, 97, 116, 97, 0, 0, 0, 0, 0, 0], "keyLen": [4] },
  // { "key": [105, 116, 101, 109, 115, 0, 0, 0, 0, 0], "keyLen": [5] },
  // { "index": [0] },
  // { "key": [112, 114, 111, 102, 105, 108, 101, 0, 0, 0], "keyLen": [7] },
  // { "key": [110, 97, 109, 101, 0, 0, 0, 0, 0, 0], "keyLen": [4] },
  // {},
];

// TODO: Configurable identifiers
var circuits = ["aes_gctr_nivc_512b", "http_nivc_512b", "json_mask_object_512b", "json_mask_array_index_512b", "json_extract_value_512b"];
var witnesses = await generateWitnessBytesForRequest(circuits, inputs);
console.log("witness", witnesses);

var hp = await getSerializedHashParams("serialized_setup_aes");
var cp = await getSerializedCircuitParams("serialized_setup_aes");
var byte_data = {
  primary_powers_g: await getByteParams("serialized_setup_aes", "powers_of_g.bytes"),
  primary_powers_h: await getByteParams("serialized_setup_aes", "powers_of_h.bytes"),
}

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
    witnesses: witnesses,
    params: {
      circuit_params: cp,
      hash_params: hp,
      byte_params: {powers_of_g: [], powers_of_h: []},
    },
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
proofWorker.postMessage({ proverConfig, byte_data, memory });

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
//     params: pp,
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
