pragma circom 2.1.9;

include "./json_universal.circom";

component main { public [step_in] } = ObjectExtractor(4000, 250, 5, 10, 200);