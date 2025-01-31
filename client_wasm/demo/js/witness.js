import { WitnessOutput } from "../pkg/client_wasm";
import { WEB_PROVER_CIRCUITS_VERSION } from "./config";

let snarkjs;
try {
  const _snarkjs = await import("snarkjs");
  snarkjs = _snarkjs;
  console.log("snarkjs loaded successfully");
} catch (error) {
  console.error("Failed to load snarkjs:", error);
  throw error;
}

const getWitnessGenerator = async function (circuit) {
  // Use self.location for workers, fallback to window.location for main thread
  const origin =
    typeof self !== "undefined" && self.location
      ? self.location.origin
      : window.location.origin;

  const wasmUrl = new URL(
    `build/circom-artifacts-1024b-v${WEB_PROVER_CIRCUITS_VERSION}/${circuit}.wasm`,
    origin,
  ).toString();
  const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  return wasm;
};

async function generateWitness(input, wasm) {
  const witStart = +Date.now();
  let wtns = { type: "mem" };
  await snarkjs.wtns.calculate(input, new Uint8Array(wasm), wtns);
  const witEnd = +Date.now();
  console.log("witgen time:", witEnd - witStart);
  return wtns;
}

const circuits_label = [
  "plaintext_authentication_1024b",
  "http_verification_1024b",
  "json_extraction_1024b",
];

export const generateWitnessBytes = async function (inputs, rom) {
  // load all circuits
  var circuits = [];
  for (let i = 0; i < circuits_label.length; i++) {
    circuits[i] = await getWitnessGenerator(circuits_label[i]);
  }

  let witnesses = [];

  for (let i = 0; i < inputs.length; i++) {
    let jsonInputs = {};
    inputs[i].forEach((value, key, map) => {
      jsonInputs[key] = value;
    });
    // load respective circuit from rom
    let wtns = await generateWitness(jsonInputs, circuits[rom[i]]);
    witnesses.push(wtns.data);
  }
  return witnesses;
};

// this is exposed via FFI to the rust code
/// it will be called there after as part of the executions trace of the prove function
export const witness = {
  createWitness: async (input, rom) => {
    console.log("createWitness", input);
    console.log("rom", rom);
    var witnesses = await generateWitnessBytes(input, rom);
    let witnesses_typed = new WitnessOutput(witnesses);
    console.log("witness", witnesses_typed);
    return witnesses_typed;
  },
};

// Modify the environment check to properly handle worker context
if (
  typeof self !== "undefined" &&
  self.constructor.name === "DedicatedWorkerGlobalScope"
) {
  console.log("Running in worker thread");
  self.witness = witness;
} else if (typeof window !== "undefined") {
  console.log("Running in main thread");
  window.witness = witness;
} else {
  console.error("Neither window nor worker context defined!");
}
