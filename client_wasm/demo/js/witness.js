import { WitnessOutput } from "../pkg/client_wasm";
const _snarkjs = import("snarkjs");
const snarkjs = await _snarkjs;

const getWitnessGenerator = async function (circuit) {
  const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/circom-artifacts-1024b-v0.8.0/`).toString();
  const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  return wasm;
}

async function generateWitness(input, wasm) {
  const witStart = +Date.now();
  let wtns = { type: "mem" };
  await snarkjs.wtns.calculate(input, new Uint8Array(wasm), wtns);
  const witEnd = +Date.now();
  console.log("witgen time:", witEnd - witStart);
  return wtns;
}

const circuits_label = ["plaintext_authentication_1024b", "http_verification_1024b", "json_extraction_1024b"];

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
  }
};


if (typeof window !== 'undefined') {
  window.witness = witness;  // For main thread
} else if (typeof self !== 'undefined') {
  self.witness = witness;    // For worker thread
}