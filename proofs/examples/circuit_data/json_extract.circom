/*
Lockfile {
    keys: [
        String(
            "k",
        ),
    ],
    value_type: String,
}
*/
pragma circom 2.1.9;

include "parser-attestor/circuits/json/interpreter.circom";

template ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen) {
    var perIterationDataLength = MAX_STACK_HEIGHT*2 + 2;
    signal input step_in[DATA_BYTES + DATA_BYTES * perIterationDataLength];

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

    signal input key1[keyLen1];
    // value starting index in `data`
    signal output value_starting_index[DATA_BYTES];
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
    signal parsing_object1_value[DATA_BYTES];
    signal is_key1_match[DATA_BYTES];
    signal is_key1_match_for_value[DATA_BYTES+1];
    is_key1_match_for_value[0] <== 0;
    signal is_next_pair_at_depth1[DATA_BYTES];

    // initialise first iteration
    parsing_key[0] <== InsideKey(MAX_STACK_HEIGHT)(stack[0], parsingData[0][0], parsingData[0][1]);

    parsing_object1_value[0] <== InsideValue()(stack[0][0], parsingData[0][0], parsingData[0][1]);
    // parsing correct value = AND(all individual stack values)
    parsing_value[0] <== MultiAND(1)([parsing_object1_value[0]]);

    is_key1_match[0] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1)(data, key1, 0, parsing_key[0], stack[0]);
    is_next_pair_at_depth1[0] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, depth1)(stack[0], data[0]);
    is_key1_match_for_value[1] <== Mux1()([is_key1_match_for_value[0] * (1-is_next_pair_at_depth1[0]), is_key1_match[0] * (1-is_next_pair_at_depth1[0])], is_key1_match[0]);
    is_value_match[0] <== MultiAND(1)([is_key1_match_for_value[1]]);

    mask[0] <== parsing_value[0] * is_value_match[0];

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

        parsing_object1_value[data_idx] <== InsideValue()(stack[data_idx][depth1], parsingData[data_idx][0], parsingData[data_idx][1]);
        // parsing correct value = AND(all individual stack values)
        parsing_value[data_idx] <== MultiAND(1)([parsing_object1_value[data_idx]]);

        // to get correct value, check:
        // - key matches at current index and depth of key is as specified
        // - whether next KV pair starts
        // - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
        is_key1_match[data_idx] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1)(data, key1, data_idx, parsing_key[data_idx], stack[data_idx]);
        is_next_pair_at_depth1[data_idx] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, depth1)(stack[data_idx], data[data_idx]);
        is_key1_match_for_value[data_idx+1] <== Mux1()([is_key1_match_for_value[data_idx] * (1-is_next_pair_at_depth1[data_idx]), is_key1_match[data_idx] * (1-is_next_pair_at_depth1[data_idx])], is_key1_match[data_idx]);
        is_value_match[data_idx] <== MultiAND(1)([is_key1_match_for_value[data_idx+1]]);

        // mask = currently parsing value and all subsequent keys matched
        mask[data_idx] <== parsing_value[data_idx] * is_value_match[data_idx];
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
}
template ExtractStringValue(TOTAL_BYTES, DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen) {
    var perIterationDataLength = MAX_STACK_HEIGHT*2 + 2;
    signal input step_in[TOTAL_BYTES];
    signal input key1[keyLen1];

    signal output step_out[TOTAL_BYTES];

    signal data[DATA_BYTES + DATA_BYTES * perIterationDataLength];
    for (var i = 0 ; i < DATA_BYTES + DATA_BYTES * perIterationDataLength ; i++) {
        data[i] <== step_in[i];
    }

    signal value_starting_index[DATA_BYTES];
    value_starting_index <== ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen)(data, key1);

    signal input_data[DATA_BYTES];
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        input_data[i] <== step_in[i];
        log("input", i, input_data[i]);
    }
    log("value_starting_index", value_starting_index[DATA_BYTES-1]+1);

    signal value[maxValueLen];
    value <== SelectSubArray(DATA_BYTES, maxValueLen)(input_data, value_starting_index[DATA_BYTES-1]+1, maxValueLen);

    for (var i = 0 ; i < maxValueLen ; i++) {
        step_out[i] <== value[i];
        log("Extract", step_out[i]);
    }
}

component main { public [step_in] } = ExtractStringValue(500, 90, 1, 4, 0, 12);