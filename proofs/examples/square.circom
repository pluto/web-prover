pragma circom 2.1.9;

template Square() {
    signal input step_in;
    signal input x;

    signal output step_out;
    signal output out;

    step_out <== step_in;
    out      <== x * x;
}

component main { public [step_in] } = Square();