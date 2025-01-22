import init, { prover, ProvingParamsWasm } from "../pkg/client_wasm";
import { witness } from "./witness";

// Override console.log and console.error
const originalConsoleLog = console.log;
const originalConsoleError = console.error;

console.log = (...args) => {
    originalConsoleLog(...args);
    postMessage({ type: 'log', data: args });
};

console.error = (...args) => {
    originalConsoleError(...args);
    postMessage({ type: 'error', data: args });
};

postMessage({ type: 'status', data: 'Worker running' });

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
    console.log("worker thread:", seconds + " seconds");
}

self.onmessage = async function (e) {
    try {
        const { proverConfig, proving_params, shared_memory } = e.data;
        await init(undefined, shared_memory);
        start();
        var pp = new ProvingParamsWasm(
            new Uint8Array(proving_params.aux_params),
        );
        console.log("proving params", proving_params);
        const proof = await prover(proverConfig, pp);
        console.log("sending proof back to main thread");
        end();
        postMessage({ type: 'proof', data: proof });
    } catch (error) {
        console.error("Error in worker:", error);
        postMessage({ type: 'error', data: error.message });
    }
}