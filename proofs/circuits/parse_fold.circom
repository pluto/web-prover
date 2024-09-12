/*
Data {
    keys: [
        String(
            "key2",
        ),
    ],
    value_type: String,
}
*/
pragma circom 2.1.9;

include "parser-attestor/circuits/json/parser/parser.circom";

template ParseFold() {
    signal input step_in[4];

    signal input byte;

    component State;
    State        = StateUpdate(1);
    State.byte <== byte;
    State.stack[0]   <== [step_in[0], step_in[1]];
    State.parsing_string <== step_in[2];
    State.parsing_number <== step_in[3];

    signal output step_out[4];
    step_out[0] <== State.next_stack[0][0];
    step_out[1] <== State.next_stack[0][1];
    step_out[2] <== State.next_parsing_string;
    step_out[3] <== State.next_parsing_number;

}


component main { public [step_in] } = ParseFold();