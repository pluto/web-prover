pragma circom 2.0.0;

include "bitify.circom";

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    component n = Num2Bits(2);
	n.in <== a;

    c <== n.out[0] * n.out[1] + b;
}

component main = Multiplier();