pragma circom 2.1.9;

include "parser-attestor/circuits/json/parser/parser.circom";

template ParseFold() {
    signal input step_in[6];

    signal input data[40];

    component State[40];
    State[0]        = StateUpdate(2);
    State[0].byte <== data[0];
    State[0].stack[0]   <== [step_in[0], step_in[1]];
    State[0].stack[1]   <== [step_in[2], step_in[3]];
    State[0].parsing_string <== step_in[4];
    State[0].parsing_number <== step_in[5];

        for(var i = 1; i < 40; i++) {
        State[i]                  = StateUpdate(2);
        State[i].byte           <== data[i];
        State[i].stack          <== State[i - 1].next_stack;
        State[i].parsing_string <== State[i - 1].next_parsing_string;
        State[i].parsing_number <== State[i - 1].next_parsing_number;
    }

    signal output step_out[6];
    step_out[0] <== State[39].next_stack[0][0];
    step_out[1] <== State[39].next_stack[0][1];
    step_out[2] <== State[39].next_stack[1][1];
    step_out[3] <== State[39].next_stack[1][1];
    step_out[4] <== State[39].next_parsing_string;
    step_out[5] <== State[39].next_parsing_number;
}


component main { public [step_in] } = ParseFold();