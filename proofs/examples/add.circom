pragma circom 2.1.9;

template Add() {
    signal input step_in;
    signal input x;
    signal input y;

    signal output step_out;
    signal output out;

    step_out <== step_in;
    out      <== x + y;
}

component main {public [step_in] } = Add();