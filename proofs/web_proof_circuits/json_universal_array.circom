pragma circom 2.1.9;

include "./json_universal.circom";

component main { public [step_in] } = JsonArrayIndexExtractNIVC(250, 5, 200);