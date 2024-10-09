/*
Response {
    version: "HTTP/1.1",
    status: "200",
    message: "OK",
    headers: {
        "Content-Type": "application/json",
    },
}
*/
pragma circom 2.1.9;

include "parser-attestor/circuits/http/interpreter.circom";
include "parser-attestor/circuits/http/parser/machine.circom";
include "parser-attestor/circuits/utils/bytes.circom";
include "parser-attestor/circuits/utils/search.circom";
include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/utils/array.circom";

template ExtractHTTPBody(TOTAL_BYTES, DATA_BYTES, maxContentLength) {
    // Raw HTTP bytestream + 5 * DATA_BYTES plaintext
    signal input step_in[TOTAL_BYTES]; // Changed this from `data`

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    // Set up mask bits for where the body of response lies
    signal output step_out[TOTAL_BYTES]; // Changed this from `body`

    signal bodyMask[DATA_BYTES];


    // Mask if parser is in the body of response
    for(var data_idx = 0; data_idx < DATA_BYTES; data_idx++) {
        bodyMask[data_idx] <== data[data_idx] * step_in[DATA_BYTES + data_idx*5 + 4];
    }

    signal bodyStartingIndex[DATA_BYTES];
    signal isZeroMask[DATA_BYTES];
    signal isPrevStartingIndex[DATA_BYTES];
    bodyStartingIndex[0] <== 0;
    isPrevStartingIndex[0] <== 0;
    isZeroMask[0] <== IsZero()(bodyMask[0]);
    for (var i=1 ; i < DATA_BYTES; i++) {
        isZeroMask[i] <== IsZero()(bodyMask[i]);
        isPrevStartingIndex[i] <== IsZero()(bodyStartingIndex[i-1]);
        bodyStartingIndex[i] <== bodyStartingIndex[i-1] + i * (1-isZeroMask[i]) * isPrevStartingIndex[i];
    }

    signal subarray[maxContentLength];

    subarray <== SelectSubArray(DATA_BYTES, maxContentLength)(bodyMask, bodyStartingIndex[DATA_BYTES-1]+1, DATA_BYTES - bodyStartingIndex[DATA_BYTES-1]);

    for (var i = 0 ; i < maxContentLength ; i++) {
        step_out[i] <== subarray[i];
        log(i, step_out[i]);
    }
}

component main { public [step_in] } = ExtractHTTPBody(4000, 320, 250);