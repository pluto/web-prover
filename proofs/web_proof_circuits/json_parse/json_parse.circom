pragma circom 2.1.9;

include "parser-attestor/circuits/json/parser/parser.circom";

template JsonParseNIVC(TOTAL_BYTES, DATA_BYTES, MAX_STACK_HEIGHT) {
    // ------------------------------------------------------------------------------------------------------------------ //
    // ~~ Set sizes at compile time ~~    
    // Total number of variables in the parser for each byte of data
    var PER_ITERATION_DATA_LENGTH = MAX_STACK_HEIGHT * 2 + 2;
    var TOTAL_BYTES_USED          = DATA_BYTES * (PER_ITERATION_DATA_LENGTH + 1);
    // ------------------------------------------------------------------------------------------------------------------ //

    // Read in from previous NIVC step (AESNIVC)
    signal input step_in[TOTAL_BYTES];

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Parse JSON ~
    // Initialize the parser
    component State[DATA_BYTES];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;
    State[0].byte           <== step_in[0];

    // Parse all the data to generate the complete parser state
    for(var i = 1; i < DATA_BYTES; i++) {
        State[i]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[i].byte           <== step_in[i];
        State[i].stack          <== State[i - 1].next_stack;
        State[i].parsing_string <== State[i - 1].next_parsing_string;
        State[i].parsing_number <== State[i - 1].next_parsing_number;
    }
    // ------------------------------------------------------------------------------------------------------------------ //

    // ------------------------------------------------------------------------------------------------------------------ //
    // ~ Write to `step_out` for next NIVC step
    // Pass the data bytes back out in the first `step_out` signals
    signal output step_out[TOTAL_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        step_out[i] <== step_in[i];
    }

    // Decode the parser state into the `step_out` remaining signals
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        for (var j = 0 ; j < MAX_STACK_HEIGHT ; j++) {
            step_out[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + j * 2]     <== State[i].next_stack[j][0];
            step_out[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + j * 2 + 1] <== State[i].next_stack[j][1];
        }
        step_out[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + MAX_STACK_HEIGHT * 2]     <== State[i].next_parsing_string;
        step_out[DATA_BYTES + i * PER_ITERATION_DATA_LENGTH + MAX_STACK_HEIGHT * 2 + 1] <== State[i].next_parsing_number;
    }
    // No need to pad as this is currently when TOTAL_BYTES == TOTAL_BYTES_USED
    // ------------------------------------------------------------------------------------------------------------------ //
}

component main { public [step_in] } = JsonParseNIVC(4160, 320, 5);

