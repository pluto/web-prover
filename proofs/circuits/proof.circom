pragma circom 2.1.9;

include "extractor/circuits/extract.circom";

template Proof() {
    signal input in;
    signal output out;

    component extractor = Extract(5,2);
    extractor.data <== [1,2,3,4,5];

    out <== 1;

}