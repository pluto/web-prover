pragma circom 2.1.9;

include "parser-attestor/circuits/json/interpreter.circom";

template ObjectExtractor(TOTAL_BYTES, DATA_BYTES, MAX_STACK_HEIGHT, maxKeyLen, maxValueLen) {
    assert(MAX_STACK_HEIGHT >= 2);

    var perIterationDataLength = MAX_STACK_HEIGHT*2 + 2;
    signal input step_in[TOTAL_BYTES];

    // Declaration of signals.
    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }

    signal stack[DATA_BYTES][MAX_STACK_HEIGHT][2];
    signal parsingData[DATA_BYTES][2];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        for (var j = 0 ; j < MAX_STACK_HEIGHT ; j++) {
            stack[i][j][0] <== step_in[DATA_BYTES + i*perIterationDataLength + j*2];
            stack[i][j][1] <== step_in[DATA_BYTES + i*perIterationDataLength + j*2 + 1];
        }
        parsingData[i][0] <== step_in[DATA_BYTES + i*perIterationDataLength + MAX_STACK_HEIGHT*2];
        parsingData[i][1] <== step_in[DATA_BYTES + i*perIterationDataLength + MAX_STACK_HEIGHT*2 + 1];
    }

    signal input key[maxKeyLen];
    signal input keyLen;

    signal output step_out[TOTAL_BYTES];

    signal value[maxValueLen];

    // Constraints.
    signal value_starting_index[DATA_BYTES];
    // flag determining whether this byte is matched value
    signal is_value_match[DATA_BYTES];
    // final mask
    signal mask[DATA_BYTES];

    // component State[DATA_BYTES];
    // State[0] = StateUpdate(MAX_STACK_HEIGHT);
    // State[0].byte           <== data[0];
    // for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
    //     State[0].stack[i]   <== [0,0];
    // }
    // State[0].parsing_string <== 0;
    // State[0].parsing_number <== 0;

    signal parsing_key[DATA_BYTES];
    signal parsing_value[DATA_BYTES];
    signal parsing_object_value[DATA_BYTES];
    signal is_key_match[DATA_BYTES];
    signal is_key_match_for_value[DATA_BYTES+1];
    is_key_match_for_value[0] <== 0;
    signal is_next_pair_at_depth[DATA_BYTES];
    signal or[DATA_BYTES];

    // initialise first iteration

    // check inside key or value
    parsing_key[0] <== InsideKey(MAX_STACK_HEIGHT)(stack[0], parsingData[0][0], parsingData[0][1]);
    parsing_value[0] <== InsideValueObject()(stack[0][0], stack[0][1], parsingData[0][0], parsingData[0][1]);

    is_key_match[0] <== KeyMatchAtDepthWithIndex(DATA_BYTES, MAX_STACK_HEIGHT, maxKeyLen, 0)(data, key, keyLen, 0, parsing_key[0], stack[0]);
    is_next_pair_at_depth[0] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, 0)(stack[0], data[0]);
    is_key_match_for_value[1] <== Mux1()([is_key_match_for_value[0] * (1-is_next_pair_at_depth[0]), is_key_match[0] * (1-is_next_pair_at_depth[0])], is_key_match[0]);
    is_value_match[0] <== parsing_value[0] * is_key_match_for_value[1];

    mask[0] <== data[0] * is_value_match[0];

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        // State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        // State[data_idx].byte           <== data[data_idx];
        // State[data_idx].stack          <== State[data_idx - 1].next_stack;
        // State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        // State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;

        // - parsing key
        // - parsing value (different for string/numbers and array)
        // - key match (key 1, key 2)
        // - is next pair
        // - is key match for value
        // - value_mask
        // - mask

        // check if inside key or not
        parsing_key[data_idx] <== InsideKey(MAX_STACK_HEIGHT)(stack[data_idx], parsingData[data_idx][0], parsingData[data_idx][1]);
        // check if inside value
        parsing_value[data_idx] <== InsideValueObject()(stack[data_idx][0], stack[data_idx][1], parsingData[data_idx][0], parsingData[data_idx][1]);

        // to get correct value, check:
        // - key matches at current index and depth of key is as specified
        // - whether next KV pair starts
        // - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
        is_key_match[data_idx] <== KeyMatchAtDepthWithIndex(DATA_BYTES, MAX_STACK_HEIGHT, maxKeyLen, 0)(data, key, keyLen, data_idx, parsing_key[data_idx], stack[data_idx]);
        is_next_pair_at_depth[data_idx] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, 0)(stack[data_idx], data[data_idx]);
        is_key_match_for_value[data_idx+1] <== Mux1()([is_key_match_for_value[data_idx] * (1-is_next_pair_at_depth[data_idx]), is_key_match[data_idx] * (1-is_next_pair_at_depth[data_idx])], is_key_match[data_idx]);
        is_value_match[data_idx] <== is_key_match_for_value[data_idx+1] * parsing_value[data_idx];

       or[data_idx] <== OR()(is_value_match[data_idx], is_value_match[data_idx - 1]);

        // mask = currently parsing value and all subsequent keys matched
        mask[data_idx] <== data[data_idx] * or[data_idx];
    }

    // find starting index of value in data by matching mask
    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(mask[0]);
    for (var i=1 ; i<DATA_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    log("value starting index", value_starting_index[DATA_BYTES-1]);
    value <== SelectSubArray(DATA_BYTES, maxValueLen)(mask, value_starting_index[DATA_BYTES-1], maxValueLen);
    for (var i = 0 ; i < maxValueLen ; i++) {
        log(i, value[i]);
        step_out[i] <== value[i];
    }
}

template ArrayIndexExtractor(TOTAL_BYTES, DATA_BYTES, MAX_STACK_HEIGHT, maxValueLen) {
    assert(MAX_STACK_HEIGHT >= 2);

    var perIterationDataLength = MAX_STACK_HEIGHT*2 + 2;
    signal input step_in[TOTAL_BYTES];

    signal data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        data[i] <== step_in[i];
    }
    signal input index;

    signal output step_out[TOTAL_BYTES];
    signal value[maxValueLen];

    signal stack[DATA_BYTES][MAX_STACK_HEIGHT][2];
    signal parsingData[DATA_BYTES][2];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        for (var j = 0 ; j < MAX_STACK_HEIGHT ; j++) {
            stack[i][j][0] <== step_in[DATA_BYTES + i*perIterationDataLength + j*2];
            stack[i][j][1] <== step_in[DATA_BYTES + i*perIterationDataLength + j*2 + 1];
        }
        parsingData[i][0] <== step_in[DATA_BYTES + i*perIterationDataLength + MAX_STACK_HEIGHT*2];
        parsingData[i][1] <== step_in[DATA_BYTES + i*perIterationDataLength + MAX_STACK_HEIGHT*2 + 1];
    }

    // value starting index in `data`
    signal value_starting_index[DATA_BYTES];
    // final mask
    signal mask[DATA_BYTES];

    // component State[DATA_BYTES];
    // State[0] = StateUpdate(MAX_STACK_HEIGHT);
    // State[0].byte           <== data[0];
    // for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
    //     State[0].stack[i]   <== [0,0];
    // }
    // State[0].parsing_string <== 0;
    // State[0].parsing_number <== 0;

    signal parsing_array[DATA_BYTES];
    signal or[DATA_BYTES];

    parsing_array[0] <== InsideArrayIndexObject()(stack[0][0], stack[0][1], parsingData[0][0], parsingData[0][1], index);
    mask[0] <== data[0] * parsing_array[0];

    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        // State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        // State[data_idx].byte           <== data[data_idx];
        // State[data_idx].stack          <== State[data_idx - 1].next_stack;
        // State[data_idx].parsing_string <== State[data_idx - 1][0];
        // State[data_idx].parsing_number <== State[data_idx - 1][1];

        parsing_array[data_idx] <== InsideArrayIndexObject()(stack[data_idx][0], stack[data_idx][1], parsingData[data_idx][0], parsingData[data_idx][1], index);

        or[data_idx] <== OR()(parsing_array[data_idx], parsing_array[data_idx - 1]);
        mask[data_idx] <== data[data_idx] * or[data_idx];
    }

    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    value_starting_index[0] <== 0;
    is_prev_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(mask[0]);
    for (var i=1 ; i<DATA_BYTES ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    log("value starting index", value_starting_index[DATA_BYTES-1]);
    value <== SelectSubArray(DATA_BYTES, maxValueLen)(mask, value_starting_index[DATA_BYTES-1], maxValueLen);
    for (var i = 0 ; i < maxValueLen ; i++) {
        log(i, value[i]);
        step_out[i] <== value[i];
    }
}