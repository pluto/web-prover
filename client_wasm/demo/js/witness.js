const _snarkjs = import("snarkjs");
const snarkjs = await _snarkjs;
import { poseidon2 } from "poseidon-lite";

const getWitnessGenerator = async function (circuit) {
  const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/target_512b/${circuit}_js/`).toString();
  const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  return wasm;
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
    // if (packedInput == BigInt(0)) {
    // hashes.push(hashes[i]);
    // } else {
    hashes.push(poseidon2([hashes[i], packedInput]));
    // }
  }

  // Return the last hash
  return hashes[Math.floor(input.length / 16)];
}

async function generateWitness(circuit, input) {
  const wasm = await getWitnessGenerator(circuit);

  console.log("wasm", wasm);

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
  let cipherText = inputs[0]["cipherText"];
  inputs[0]["step_in"] = 0;
  for (var i = 0; i < plaintext_length / 16; i++) {
    inputs[0]["plainText"] = plaintext.slice(i * 16, (i + 1) * 16);
    inputs[0]["cipherText"] = cipherText.slice(i * 16, (i + 1) * 16);
    inputs[0]["ctr"] = [0, 0, 0, i + 1];
    console.log("inputs[0]", inputs[0]);
    let wtns = await generateWitness(circuits[0], inputs[0]);
    witnesses.push({
      val: wtns.data
    });
    inputs[0]["step_in"] = DataHasher(plaintext.slice(0, (i + 1) * 16));
  };

  // HTTP
  // console.log(http_start_line.length)
  // let http_start_line_padded = http_start_line.concat(Array(Math.max(0, 512 - http_start_line.length)).fill(0));
  // let http_header_0_padded = http_header_0.concat(Array(Math.max(0, 512 - http_header_0.length)).fill(0));
  // let http_header_1_padded = http_header_1.concat(Array(Math.max(0, 512 - http_header_1.length)).fill(0));
  // let http_body_padded = http_body.concat(Array(Math.max(0, 512 - http_body.length)).fill(0));

  // inputs[1]["start_line_hash"] = DataHasher(http_start_line_padded);
  // let http_header_0_hash = DataHasher(http_header_0_padded);
  // let http_header_1_hash = DataHasher(http_header_1_padded);
  // inputs[1]["header_hashes"] = [http_header_0_hash, http_header_1_hash, 0, 0, 0];
  // inputs[1]["body_hash"] = DataHasher(http_body_padded);
  // inputs[1]["step_in"] = DataHasher(extendedHTTPInput);
  // console.log("http", inputs[1]);
  // let wtns = await generateWitness(circuits[1], inputs[1]);
  // witnesses.push({
  //     val: wtns.data
  // });

  // console.log("json mask object");
  // let wtnsJson = await generateWitness(circuits[4], inputs[4]);
  // witnesses.push({
  //   val: wtnsJson.data,
  // });

  // console.log("json extract value");
  // let wtnsFinal = await generateWitness(circuits[6], inputs[6]);
  // console.log("wtnsFinal", wtnsFinal);
  // witnesses.push({
  //   val: wtnsFinal.data,
  // });

  return witnesses;
};

const circuits = ["aes_gctr_nivc_512b", "http_nivc_512b", "json_mask_object_512b", "json_mask_array_index_512b", "json_extract_value_512b"];

// witness.js
export const witness = {
  async createWitness(input) {
    // Implement your witness creation logic here
    // This is just an example implementation
    let inputs = [
      {
        "key": input.key,
        "iv": input.iv,
        "plainText": input.plaintext,
        "cipherText": input.ciphertext,
        "ctr": [0, 0, 0, 0],
        "aad": input.aad,
        "step_in": 0,
      }
    ];

    var witnesses = await generateWitnessBytes(circuits, inputs);
    console.log("print shit", witnesses);
    const result = {
      data: witnesses[0],
    };
    return result;
  }
};

// Make it globally available
if (typeof window !== 'undefined') {
  window.witness = witness;  // For main thread
} else if (typeof self !== 'undefined') {
  self.witness = witness;    // For worker thread
}

// export { witness };