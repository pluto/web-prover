pragma circom 2.1.9;

include "./json_universal.circom";

component main { public [step_in] } = ArrayIndexExtractor(4000, 250, 5, 200);