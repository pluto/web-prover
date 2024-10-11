pragma circom 2.1.9;

include "parser-attestor/circuits/http/interpreter.circom";

template LockHeader(TOTAL_BYTES, DATA_BYTES, headerNameLen, headerValueLen) {
    // DATA_BYTES + 5*DATA_BYTES
    signal input step_in[TOTAL_BYTES];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    signal input header[headerNameLen];
    signal input value[headerValueLen];

    // TODO: This likely uses an underconstrained circuit, but we redo it with a different impl
    component headerNameLocation = SubstringMatch(DATA_BYTES, headerNameLen);
    headerNameLocation.data      <== data;
    headerNameLocation.key       <== header;

    component headerFieldNameValueMatch;

    headerFieldNameValueMatch             =  HeaderFieldNameValueMatch(DATA_BYTES, headerNameLen, headerValueLen);
    headerFieldNameValueMatch.data        <== data;
    headerFieldNameValueMatch.headerName  <== header;
    headerFieldNameValueMatch.headerValue <== value;
    headerFieldNameValueMatch.index       <== headerNameLocation.position;

    // TODO: Make this assert we are parsing header
    // This is the assertion that we have locked down the correct header
    headerFieldNameValueMatch.out === 1;

    signal output step_out[TOTAL_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        // add plaintext http input to step_out
        step_out[i] <== step_in[i];

        // add parser state
        step_out[DATA_BYTES + i*5]     <== step_in[DATA_BYTES + i*5];
        step_out[DATA_BYTES + i*5 + 1] <== step_in[DATA_BYTES + i*5 + 1];
        step_out[DATA_BYTES + i*5 + 2] <== step_in[DATA_BYTES + i*5 + 2];
        step_out[DATA_BYTES + i*5 + 3] <== step_in[DATA_BYTES + i*5 + 3];
        step_out[DATA_BYTES + i*5 + 4] <== step_in[DATA_BYTES + i*5 + 4];
    }
}

component main { public [step_in] } = LockHeader(4000, 320, 12, 31);