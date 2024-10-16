pragma circom 2.1.9;

include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/utils/array.circom";

template MaskExtractFinal(TOTAL_BYTES, maxValueLen) {
    signal input step_in[TOTAL_BYTES];
    signal output step_out[TOTAL_BYTES];

    signal is_zero_mask[TOTAL_BYTES];
    signal is_prev_starting_index[TOTAL_BYTES];
    signal value_starting_index[TOTAL_BYTES];

    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(step_in[0]);
    for (var i=1 ; i<TOTAL_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(step_in[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    // log("value starting index", value_starting_index[TOTAL_BYTES-1]);

    signal value[maxValueLen] <== SelectSubArray(TOTAL_BYTES, maxValueLen)(step_in, value_starting_index[TOTAL_BYTES-1], maxValueLen);
    for (var i = 0 ; i < maxValueLen ; i++) {
        // log(i, value[i]);
        step_out[i] <== value[i];
    }
    for (var i = maxValueLen ; i < TOTAL_BYTES ; i++) {
        step_out[i] <== 0;
    }
}

component main { public [step_in] } = MaskExtractFinal(4160, 200);