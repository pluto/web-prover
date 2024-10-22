pragma circom 2.1.9;

include "parser-attestor/circuits/http/parser/machine.circom";
include "parser-attestor/circuits/http/interpreter.circom";
include "parser-attestor/circuits/utils/bytes.circom";

// TODO: Note that TOTAL_BYTES will match what we have for AESGCMFOLD step_out
// I have not gone through to double check the sizes of everything yet.
template LockStartLine(TOTAL_BYTES, DATA_BYTES, beginningLen, middleLen, finalLen) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~
    // Total number of variables in the parser for each byte of data
    var AES_BYTES                 = DATA_BYTES + 50; // TODO: Might be wrong, but good enough for now
    var PER_ITERATION_DATA_LENGTH = 5;
    var TOTAL_BYTES_USED          = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1); // data + parser vars
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Unravel from previous NIVC step ~
    // Read in from previous NIVC step (JsonParseNIVC)
    signal input step_in[TOTAL_BYTES];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[50 + i];
    }

    // // TODO: check if these needs to here or not
    // component dataASCII = ASCII(DATA_BYTES);
    // dataASCII.in <== data;

    signal input beginning[beginningLen];
    signal input middle[middleLen];
    signal input final[finalLen];

    // Initialze the parser
    component State[DATA_BYTES];
    State[0]                     = HttpStateUpdate();
    State[0].byte                <== data[0];
    State[0].parsing_start       <== 1;
    State[0].parsing_header      <== 0;
    State[0].parsing_field_name  <== 0;
    State[0].parsing_field_value <== 0;
    State[0].parsing_body        <== 0;
    State[0].line_status         <== 0;

    /*
    Note, because we know a beginning is the very first thing in a request
    we can make this more efficient by just comparing the first `beginningLen` bytes
    of the data ASCII against the beginning ASCII itself.
    */
    // Check first beginning byte
    signal beginningIsEqual[beginningLen];
    beginningIsEqual[0] <== IsEqual()([data[0],beginning[0]]);
    beginningIsEqual[0] === 1;

    // Setup to check middle bytes
    signal startLineMask[DATA_BYTES];
    signal middleMask[DATA_BYTES];
    signal finalMask[DATA_BYTES];

    var middle_start_counter = 1;
    var middle_end_counter = 1;
    var final_end_counter = 1;
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                     = HttpStateUpdate();
        State[data_idx].byte                <== data[data_idx];
        State[data_idx].parsing_start       <== State[data_idx - 1].next_parsing_start;
        State[data_idx].parsing_header      <== State[data_idx - 1].next_parsing_header;
        State[data_idx].parsing_field_name  <== State[data_idx - 1].next_parsing_field_name;
        State[data_idx].parsing_field_value <== State[data_idx - 1].next_parsing_field_value;
        State[data_idx].parsing_body        <== State[data_idx - 1].next_parsing_body;
        State[data_idx].line_status         <== State[data_idx - 1].next_line_status;

        // Check remaining beginning bytes
        if(data_idx < beginningLen) {
            beginningIsEqual[data_idx] <== IsEqual()([data[data_idx], beginning[data_idx]]);
            beginningIsEqual[data_idx] === 1;
        }

        // Set the masks based on parser state
        startLineMask[data_idx] <== inStartLine()(State[data_idx].parsing_start);
        middleMask[data_idx]    <== inStartMiddle()(State[data_idx].parsing_start);
        finalMask[data_idx]     <== inStartEnd()(State[data_idx].parsing_start);

        // Increment counters based on mask information
        middle_start_counter += startLineMask[data_idx] - middleMask[data_idx] - finalMask[data_idx];
        middle_end_counter   += startLineMask[data_idx] - finalMask[data_idx];
        final_end_counter    += startLineMask[data_idx];
    }

    // Additionally verify beginning had correct length
    beginningLen === middle_start_counter - 1;

    // Check middle is correct by substring match and length check
    signal middleMatch <== SubstringMatchWithIndex(DATA_BYTES, middleLen)(data, middle, middle_start_counter);
    middleMatch === 1;
    middleLen === middle_end_counter - middle_start_counter - 1;

    // Check final is correct by substring match and length check
    signal finalMatch <== SubstringMatchWithIndex(DATA_BYTES, finalLen)(data, final, middle_end_counter);
    finalMatch === 1;
    // -2 here for the CRLF
    finalLen === final_end_counter - middle_end_counter - 2;

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write out to next NIVC step (Lock Header)
    signal output step_out[TOTAL_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        // add plaintext http input to step_out
        step_out[i] <== step_in[50 + i];

        // add parser state
        step_out[DATA_BYTES + i * 5]     <== State[i].next_parsing_start;
        step_out[DATA_BYTES + i * 5 + 1] <== State[i].next_parsing_header;
        step_out[DATA_BYTES + i * 5 + 2] <== State[i].next_parsing_field_name;
        step_out[DATA_BYTES + i * 5 + 3] <== State[i].next_parsing_field_value;
        step_out[DATA_BYTES + i * 5 + 4] <== State[i].next_parsing_body;
    }
    // Pad remaining with zeros
    for (var i = TOTAL_BYTES_USED ; i < TOTAL_BYTES ; i++ ) {
        step_out[i] <== 0;
    }
}

component main { public [step_in] } = LockStartLine(4160, 320, 8, 3, 2);