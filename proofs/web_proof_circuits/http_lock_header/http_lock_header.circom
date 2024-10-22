pragma circom 2.1.9;

include "parser-attestor/circuits/http/interpreter.circom";
include "parser-attestor/circuits/utils/array.circom";

template LockHeader(TOTAL_BYTES, DATA_BYTES, headerNameLen, headerValueLen) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~    
    // Total number of variables in the parser for each byte of data
    var PER_ITERATION_DATA_LENGTH = 5;
    var TOTAL_BYTES_USED          = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1); // data + parser vars
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (HttpParseAndLockStartLine or HTTPLockHeader)
    signal input step_in[TOTAL_BYTES];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    signal input header[headerNameLen];
    signal input value[headerValueLen];

    component headerNameLocation = FirstStringMatch(DATA_BYTES, headerNameLen);
    headerNameLocation.data      <== data;
    headerNameLocation.key       <== header;

    component headerFieldNameValueMatch;
    headerFieldNameValueMatch             =  HeaderFieldNameValueMatch(DATA_BYTES, headerNameLen, headerValueLen);
    headerFieldNameValueMatch.data        <== data;
    headerFieldNameValueMatch.headerName  <== header;
    headerFieldNameValueMatch.headerValue <== value;
    headerFieldNameValueMatch.index       <== headerNameLocation.position;

    // TODO: Make this assert we are parsing header!!!
    // This is the assertion that we have locked down the correct header
    headerFieldNameValueMatch.out === 1;

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write out to next NIVC step
    signal output step_out[TOTAL_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        // add plaintext http input to step_out
        step_out[i] <== step_in[i];

        // add parser state
        step_out[DATA_BYTES + i * 5]     <== step_in[DATA_BYTES + i * 5];
        step_out[DATA_BYTES + i * 5 + 1] <== step_in[DATA_BYTES + i * 5 + 1];
        step_out[DATA_BYTES + i * 5 + 2] <== step_in[DATA_BYTES + i * 5 + 2];
        step_out[DATA_BYTES + i * 5 + 3] <== step_in[DATA_BYTES + i * 5 + 3];
        step_out[DATA_BYTES + i * 5 + 4] <== step_in[DATA_BYTES + i * 5 + 4];
    }
        // Pad remaining with zeros
    for (var i = TOTAL_BYTES_USED ; i < TOTAL_BYTES ; i++ ) {
        step_out[i] <== 0;
    }
}

// TODO: Handrolled template that I haven't tested YOLO.
template FirstStringMatch(dataLen, keyLen) {
    signal input data[dataLen];
    signal input key[keyLen];
    signal output position;

    var matched = 0;
    var counter = 0;
    component stringMatch[dataLen - keyLen];
    component hasMatched[dataLen - keyLen];
    for (var idx = 0 ; idx < dataLen - keyLen ; idx++) {
        stringMatch[idx] = IsEqualArray(keyLen);
        stringMatch[idx].in[0] <== key;
        for (var key_idx = 0 ; key_idx < keyLen ; key_idx++) {
            stringMatch[idx].in[1][key_idx] <== data[idx + key_idx] * (1 - matched);
        }
        hasMatched[idx] = IsEqual();
        hasMatched[idx].in <== [stringMatch[idx].out, 1];
        matched += hasMatched[idx].out;
        counter += (1 - matched); // TODO: Off by one? Move before?
    }
    position <== counter;
}

component main { public [step_in] } = LockHeader(4160, 320, 12, 31);

