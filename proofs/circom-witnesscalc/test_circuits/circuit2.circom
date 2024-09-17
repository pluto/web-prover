pragma circom 2.0.0;

include "comparators.circom";

function f2(N) {
    if (N >= 10) { return 2; }
	else { return 3; }
}

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    var d = f2(30);

    component e = IsZero();
    e.in <== a;
    c <== e.out * b + d;
}

component main = Multiplier();