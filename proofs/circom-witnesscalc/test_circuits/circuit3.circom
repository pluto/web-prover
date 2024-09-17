pragma circom 2.0.0;

template T2() {
    signal input a[2];
	signal output b;

    b <== a[0] * a[1] + 3;
}

template Multiplier() {
    signal input a;
    signal input b;

    signal d[2];

    signal output c;

    d[0] <== a;
	d[1] <== b;

    c <== T2()(d);
}

component main = Multiplier();