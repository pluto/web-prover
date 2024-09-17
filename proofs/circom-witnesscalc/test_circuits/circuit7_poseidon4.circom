pragma circom 2.0.0;

include "poseidon.circom";

template Pos() {
    signal input a[4];
    signal output c;

    component p = Poseidon(4);
	p.inputs[0] <== a[0];
	p.inputs[1] <== a[1];
	p.inputs[2] <== a[2];
	p.inputs[3] <== a[3];
	c <== p.out;
}

component main = Pos();