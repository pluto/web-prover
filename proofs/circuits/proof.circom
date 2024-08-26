pragma circom 2.1.9;

include "extractor/circuits/extract.circom";

template Proof() {
    signal input in[5];
    signal output out;

    component extractor = Extract(5,2);
    extractor.data <== in;

    out <== 1;

}