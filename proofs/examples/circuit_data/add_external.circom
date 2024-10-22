pragma circom 2.1.9;

template AddIntoZeroth() {
    signal input step_in[2];
    signal input external[2];

    signal output step_out[2];

    step_out[0] <== step_in[0] + external[0];
    step_out[1] <== step_in[1] + external[1];
}

component main {public [step_in] } = AddIntoZeroth();