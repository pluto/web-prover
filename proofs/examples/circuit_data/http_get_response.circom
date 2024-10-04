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

template LockHTTPResponse(TOTAL_BYTES, DATA_BYTES, maxContentLength, versionLen, statusLen, messageLen, headerNameLen1, headerValueLen1) {
    // Raw HTTP bytestream
    signal input step_in[TOTAL_BYTES]; // Changed this from `data`
    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[50 + i];
    }

    // Status line attributes
    signal input version[versionLen];
    signal input status[statusLen];
    signal input message[messageLen];

    // Header names and values to lock
    signal input header1[headerNameLen1];
    signal input value1[headerValueLen1];

    // Set up mask bits for where the body of response lies
    signal output step_out[TOTAL_BYTES]; // Changed this from `body`

    signal bodyMask[DATA_BYTES];

    // Check first version byte
    signal versionIsEqual[versionLen];
    versionIsEqual[0] <== IsEqual()([data[0],version[0]]);
    versionIsEqual[0] === 1;

    // Setup to check status and message bytes
    signal startLineMask[DATA_BYTES];
    signal statusMask[DATA_BYTES];
    signal messageMask[DATA_BYTES];

    var status_start_counter = 0;
    var status_end_counter   = 0;
    var message_end_counter  = 0;
    signal headerNameValueMatch1[DATA_BYTES];
    var hasMatchedHeaderValue1 = 0;

    component State[DATA_BYTES];
    State[0]                       = HttpStateUpdate();
    State[0].byte                <== data[0];
    State[0].parsing_start       <== 1;
    State[0].parsing_header      <== 0;
    State[0].parsing_field_name  <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body        <== 0;
    State[0].line_status         <== 0;

    // Mask if parser is in the body of response
    bodyMask[0] <== data[0] * State[0].next_parsing_body;

    // Get the status bytes
    startLineMask[0]     <== inStartLine()(State[0].next_parsing_start);
    statusMask[0]        <== inStartMiddle()(State[0].next_parsing_start);
    messageMask[0]       <== inStartEnd()(State[0].next_parsing_start);
    status_start_counter += startLineMask[0] - statusMask[0] - messageMask[0];

    // Get the message bytes
    status_end_counter          += startLineMask[0] - messageMask[0];
    message_end_counter         += startLineMask[0];
    headerNameValueMatch1[0]    <== HeaderFieldNameValueMatch(DATA_BYTES, headerNameLen1, headerValueLen1)(data, header1, value1, 0);
    hasMatchedHeaderValue1      += headerNameValueMatch1[0];

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                       = HttpStateUpdate();
        State[data_idx].byte                <== data[data_idx];
        State[data_idx].parsing_start       <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header      <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name  <== State[data_idx-1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx-1].next_parsing_field_value;
        State[data_idx].parsing_body        <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status         <== State[data_idx - 1].next_line_status;


        // Mask if parser is in the body of response
        bodyMask[data_idx] <== data[data_idx] * State[data_idx].next_parsing_body;

        // Check remaining version bytes
        if(data_idx < versionLen) {
            versionIsEqual[data_idx] <== IsEqual()([data[data_idx], version[data_idx]]);
            versionIsEqual[data_idx] === 1;
        }

        // Get the status bytes
        startLineMask[data_idx]    <== inStartLine()(State[data_idx].next_parsing_start);
        statusMask[data_idx]       <== inStartMiddle()(State[data_idx].next_parsing_start);
        messageMask[data_idx]      <== inStartEnd()(State[data_idx].next_parsing_start);
        status_start_counter        += startLineMask[data_idx] - statusMask[data_idx] - messageMask[data_idx];

        // Get the message bytes
        status_end_counter          += startLineMask[data_idx] - messageMask[data_idx];
        message_end_counter         += startLineMask[data_idx];
        headerNameValueMatch1[data_idx] <== HeaderFieldNameValueMatch(DATA_BYTES, headerNameLen1, headerValueLen1)(data, header1, value1, data_idx);
        hasMatchedHeaderValue1 += headerNameValueMatch1[data_idx];
    }

    _ <== State[DATA_BYTES-1].next_line_status;
    _ <== State[DATA_BYTES-1].next_parsing_start;
    _ <== State[DATA_BYTES-1].next_parsing_header;
    _ <== State[DATA_BYTES-1].next_parsing_field_name;
    _ <== State[DATA_BYTES-1].next_parsing_field_value;


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
    }

    // Verify version had correct length
    versionLen === status_start_counter;

    // Check status is correct by substring match and length check
    signal statusMatch <== SubstringMatchWithIndex(DATA_BYTES, statusLen)(data, status, status_start_counter + 1);
    statusMatch        === 1;
    statusLen          === status_end_counter - status_start_counter - 1;

    // Check message is correct by substring match and length check
    signal messageMatch <== SubstringMatchWithIndex(DATA_BYTES, messageLen)(data, message, status_end_counter + 1);
    messageMatch        === 1;
    // -2 here for the CRLF
    messageLen          === message_end_counter - status_end_counter - 2;
    hasMatchedHeaderValue1 === 1;

    for (var i = 0 ; i < maxContentLength ; i++) {
        log(i, step_out[i]);
    }
}
component main { public [step_in] } = LockHTTPResponse(500,208,90,8,3,2,12,31);