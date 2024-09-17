pragma circom 2.0.0;

include "poseidon.circom";

template Pos() {
    signal input a;
    signal output c;

    component p = Poseidon(1);
	p.inputs[0] <== a;
	c <== p.out;
}

component main = Pos();