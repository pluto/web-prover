pragma circom 2.0.0;

include "bitify.circom";

template cutId() {
	signal input in;
	signal output out;

	signal idBits[256] <== Num2Bits(256)(in);

	component cut = Bits2Num(256-16-16-8);
	for (var i=16; i<256-16-8; i++) {
		cut.in[i-16] <== idBits[i];
	}
	out <== cut.out;
}


template Main() {
    signal input a;
    signal output c;

    component p = cutId();
	p.in <== a;
	c <== p.out;
}


component main = Main();