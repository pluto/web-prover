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

include "parser-attestor/circuits/json/parser/machine.circom";

template ParseRaw() {
    signal input data[2];

    component State[2];
    State[0]        = StateUpdate(2);
    State[0].byte <== data[0];
    State[0].stack[0]   <== [0,0];
    State[0].stack[1]   <== [0,0];
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    for(var i = 1; i < 2; i++) {
        State[i]                  = StateUpdate(2);
        State[i].byte           <== data[i];
        State[i].stack          <== State[i - 1].next_stack;
        State[i].parsing_string <== State[i - 1].next_parsing_string;
        State[i].parsing_number <== State[i - 1].next_parsing_number;
    }

}


// component main = ParseRaw();