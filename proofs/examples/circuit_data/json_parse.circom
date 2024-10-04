pragma circom 2.1.9;

include "parser-attestor/circuits/json/parser/parser.circom";

template ParseFold(TOTAL_BYTES, DATA_BYTES, MAX_STACK_HEIGHT) {
    signal input step_in[TOTAL_BYTES];

    component State[DATA_BYTES];
    State[0]        = StateUpdate(MAX_STACK_HEIGHT);
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;
    State[0].byte <== step_in[0];

    for(var i = 1; i < DATA_BYTES; i++) {
        State[i]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[i].byte           <== step_in[i];
        State[i].stack          <== State[i - 1].next_stack;
        State[i].parsing_string <== State[i - 1].next_parsing_string;
        State[i].parsing_number <== State[i - 1].next_parsing_number;
    }

    var perIterationDataLength = MAX_STACK_HEIGHT*2 + 2;
    signal output step_out[TOTAL_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        step_out[i] <== step_in[i];
    }

    for (var i = 0 ; i < DATA_BYTES ; i++) {
        for (var j = 0 ; j < MAX_STACK_HEIGHT ; j++) {
            step_out[DATA_BYTES + i*perIterationDataLength + j*2]     <== State[i].next_stack[j][0];
            step_out[DATA_BYTES + i*perIterationDataLength + j*2 + 1] <== State[i].next_stack[j][1];
        }
        step_out[DATA_BYTES + i*perIterationDataLength + MAX_STACK_HEIGHT*2]    <== State[i].next_parsing_string;
        step_out[DATA_BYTES + i*perIterationDataLength + MAX_STACK_HEIGHT*2 + 1] <== State[i].next_parsing_number;
    }
}


component main { public [step_in] } = ParseFold(500, 90, 1);