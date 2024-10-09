pragma circom 2.1.9;

include "parser-attestor/circuits/http/interpreter.circom";

// TODO: maybe do not need full parser state
template LockHeader(TOTAL_BYTES, DATA_BYTES, headerNameLen, headerValueLen) {
    // DATA_BYTES + 5*DATA_BYTES
    signal input step_in[TOTAL_BYTES];


    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    signal input header[headerNameLen];
    signal input value[headerValueLen];

    //--------------------------------------------------------------------------------------------//
    //-CONSTRAINTS--------------------------------------------------------------------------------//
    //--------------------------------------------------------------------------------------------//
    // component dataASCII = ASCII(DATA_BYTES);
    // dataASCII.in <== data;
    //--------------------------------------------------------------------------------------------//

    // Initialze the parser
    // component State[DATA_BYTES];
    // State[0] = HttpStateUpdate();
    // State[0].byte           <== data[0];
    // State[0].parsing_start  <== 1;
    // State[0].parsing_header <== 0;
    // State[0].parsing_field_name <== 0;
    // State[0].parsing_field_value <== 0;
    // State[0].parsing_body   <== 0;
    // State[0].line_status    <== 0;

    component headerFieldNameValueMatch[DATA_BYTES];
    signal isHeaderFieldNameValueMatch[DATA_BYTES];

    // initalise as 0, because start line won't match
    isHeaderFieldNameValueMatch[0] <== 0;
    var hasMatched = 0;

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        // State[data_idx]                  = HttpStateUpdate();
        // State[data_idx].byte           <== data[data_idx];
        // State[data_idx].parsing_start  <== State[data_idx - 1].next_parsing_start;
        // State[data_idx].parsing_header <== State[data_idx - 1].next_parsing_header;
        // State[data_idx].parsing_field_name <== State[data_idx-1].next_parsing_field_name;
        // State[data_idx].parsing_field_value <== State[data_idx-1].next_parsing_field_value;
        // State[data_idx].parsing_body   <== State[data_idx - 1].next_parsing_body;
        // State[data_idx].line_status    <== State[data_idx - 1].next_line_status;

        headerFieldNameValueMatch[data_idx] =  HeaderFieldNameValueMatch(DATA_BYTES, headerNameLen, headerValueLen);
        headerFieldNameValueMatch[data_idx].data <== data;
        headerFieldNameValueMatch[data_idx].headerName <== header;
        headerFieldNameValueMatch[data_idx].headerValue <== value;
        headerFieldNameValueMatch[data_idx].index <== data_idx;
        isHeaderFieldNameValueMatch[data_idx] <== isHeaderFieldNameValueMatch[data_idx-1] + headerFieldNameValueMatch[data_idx].out * step_in[DATA_BYTES + (data_idx * 5) + 1];



        // Debugging
        // log("State[", data_idx, "].parsing_start      ", "= ", State[data_idx].parsing_start);
        // log("State[", data_idx, "].parsing_header     ", "= ", State[data_idx].parsing_header);
        // log("State[", data_idx, "].parsing_field_name ", "= ", State[data_idx].parsing_field_name);
        // log("State[", data_idx, "].parsing_field_value", "= ", State[data_idx].parsing_field_value);
        // log("State[", data_idx, "].parsing_body       ", "= ", State[data_idx].parsing_body);
        // log("State[", data_idx, "].line_status        ", "= ", State[data_idx].line_status);
        // log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    // Debugging
    // log("State[", DATA_BYTES, "].parsing_start      ", "= ", State[DATA_BYTES-1].next_parsing_start);
    // log("State[", DATA_BYTES, "].parsing_header     ", "= ", State[DATA_BYTES-1].next_parsing_header);
    // log("State[", DATA_BYTES, "].parsing_field_name ", "= ", State[DATA_BYTES-1].parsing_field_name);
    // log("State[", DATA_BYTES, "].parsing_field_value", "= ", State[DATA_BYTES-1].parsing_field_value);
    // log("State[", DATA_BYTES, "].parsing_body       ", "= ", State[DATA_BYTES-1].next_parsing_body);
    // log("State[", DATA_BYTES, "].line_status        ", "= ", State[DATA_BYTES-1].next_line_status);
    // log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    isHeaderFieldNameValueMatch[DATA_BYTES - 1] === 1;

    signal output step_out[TOTAL_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        // add plaintext http input to step_out
        step_out[i] <== step_in[i];

        // add parser state
        step_out[DATA_BYTES + i*5] <== step_in[DATA_BYTES + i*5];
        step_out[DATA_BYTES + i*5 + 1] <== step_in[DATA_BYTES + i*5 + 1];
        step_out[DATA_BYTES + i*5 + 2] <== step_in[DATA_BYTES + i*5 + 2];
        step_out[DATA_BYTES + i*5 + 3] <== step_in[DATA_BYTES + i*5 + 3];
        step_out[DATA_BYTES + i*5 + 4] <== step_in[DATA_BYTES + i*5 + 4];
    }
}

component main { public [step_in] } = LockHeader(4000, 320, 12, 31);