pragma circom 2.0.0;

function f2(N) {
    if (N >= 10) { return 2; }
	else { return 3; }
}

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    var d = f2(30);

    c <== a * b + d;
}

component main = Multiplier();