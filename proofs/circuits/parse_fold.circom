pragma circom 2.1.9;

include "parser-attestor/circuits/json/parser/parser.circom";

template ParseFold() {
    signal input step_in[6];

    signal input byte;

    component State;
    State                  = StateUpdate(2);
    State.byte           <== byte;
    State.stack[0]       <== [step_in[0], step_in[1]];
    State.stack[1]       <== [step_in[2], step_in[3]];
    State.parsing_string <== step_in[4];
    State.parsing_number <== step_in[5];

    State: { Stack, ParsingString, ParsingNumber }

    signal output step_out[6];
    step_out[0] <== State.next_stack[0][0];
    step_out[1] <== State.next_stack[0][1];
    step_out[2] <== State.next_stack[1][1];
    step_out[3] <== State.next_stack[1][1];
    step_out[4] <== State.next_parsing_string;
    step_out[5] <== State.next_parsing_number;
}


component main { public [step_in] } = ParseFold();