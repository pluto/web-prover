pragma circom 2.1.9;

include "parser-attestor/circuits/http/interpreter.circom";

template HTTPMaskBodyNIVC(TOTAL_BYTES, DATA_BYTES) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~    
    // Total number of variables in the parser for each byte of data
    var PER_ITERATION_DATA_LENGTH = 5;
    // -> var TOTAL_BYTES         = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1); // data + parser vars
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (HttpParseAndLockStartLine or HTTPLockHeader)
    signal input step_in[TOTAL_BYTES];

    signal data[DATA_BYTES];
    signal parsing_body[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i]         <== step_in[i];
        parsing_body[i] <== step_in[DATA_BYTES + i * 5 + 4];
    }

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write out to next NIVC step
    signal output step_out[TOTAL_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        step_out[i] <== data[i] * parsing_body[i];
    }
    // Write out padded with zeros
    for (var i = DATA_BYTES ; i < TOTAL_BYTES ; i++) {
        step_out[i] <== 0;
    }
}

component main { public [step_in] } = HTTPMaskBodyNIVC(4160, 320);

