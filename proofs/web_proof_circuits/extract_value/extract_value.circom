pragma circom 2.1.9;

include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/utils/array.circom";

template MaskExtractFinal(TOTAL_BYTES, DATA_BYTES, maxValueLen) {
    signal input step_in[TOTAL_BYTES + 1];
    signal output step_out[TOTAL_BYTES + 1];

    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    signal value_starting_index[DATA_BYTES];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(step_in[0]);
    for (var i=1 ; i<DATA_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(step_in[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    signal value[maxValueLen] <== SelectSubArray(DATA_BYTES, maxValueLen)(data, value_starting_index[DATA_BYTES-1], maxValueLen);
    for (var i = 0 ; i < maxValueLen ; i++) {
        // log(i, value[i]);
        step_out[i] <== value[i];
    }
    for (var i = maxValueLen ; i < TOTAL_BYTES ; i++) {
        step_out[i] <== 0;
    }
    step_out[TOTAL_BYTES] <== 0;
}

component main { public [step_in] } = MaskExtractFinal(4160, 320, 200);