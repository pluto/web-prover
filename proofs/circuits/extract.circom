/*
Data {
    keys: [
        String(
            "key2",
        ),
    ],
    value_type: String,
}
*/
pragma circom 2.1.9;

include "parser-attestor/circuits/json/interpreter.circom";

template ExtractValue(DATA_BYTES, PER_FOLD_LENGTH, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen) {
    // stack, parsing_string, parsing_number, is_key1_match_for_value, value_starting_index, curr_fold_index
    var fold_input_len = MAX_STACK_HEIGHT*2+5;
    signal input step_in[fold_input_len];

    signal input data[DATA_BYTES];
    signal input data_fold[PER_FOLD_LENGTH];
    signal input key1[keyLen1];

    // r must be secret, so either has to be derived from hash in the circuit or off the circuit
    // TODO: this need to be handled better
    // can be added as input or removed altogether
    component rHasher = PoseidonModular(DATA_BYTES +  keyLen1);
    for (var i = 0 ; i < keyLen1 ; i++) {
        rHasher.in[i] <== key1[i];
    }
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        rHasher.in[i + keyLen1] <== data[i];
    }
    signal r <== rHasher.out;

    // TODO: add a array match at `CURR_FOLD_INDEX` for data and data_fold
    // signal CURR_FOLD_INDEX <== step_in[MAX_STACK_HEIGHT*2 + 4];


    signal value_starting_index[PER_FOLD_LENGTH];

    signal mask[PER_FOLD_LENGTH];
    // mask[0] <== 0;

    component State[PER_FOLD_LENGTH];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [step_in[i*2], step_in[i*2+1]];
    }
    State[0].parsing_string <== step_in[MAX_STACK_HEIGHT*2];
    State[0].parsing_number <== step_in[MAX_STACK_HEIGHT*2+1];


    signal parsing_key[PER_FOLD_LENGTH];
    signal parsing_value[PER_FOLD_LENGTH];
    signal parsing_object1_value[PER_FOLD_LENGTH];
    signal is_key1_match[PER_FOLD_LENGTH];
    signal is_key1_match_for_value[PER_FOLD_LENGTH+1];
    is_key1_match_for_value[0] <== step_in[MAX_STACK_HEIGHT*2+2];
    signal is_next_pair_at_depth1[PER_FOLD_LENGTH];

    signal is_value_match[PER_FOLD_LENGTH];
    signal value_mask[PER_FOLD_LENGTH];

    parsing_key[0] <== InsideKey(MAX_STACK_HEIGHT)(State[0].next_stack, State[0].next_parsing_string, State[0].next_parsing_number);
    parsing_object1_value[0] <== InsideValueAtDepth(MAX_STACK_HEIGHT, depth1)(State[0].next_stack, State[0].next_parsing_string, State[0].next_parsing_number);
    parsing_value[0] <== MultiAND(1)([parsing_object1_value[0]]);

    signal data_index[PER_FOLD_LENGTH];
    data_index[0] <== step_in[MAX_STACK_HEIGHT*2 + 4] * PER_FOLD_LENGTH;

    is_key1_match[0] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1)(data, key1, r, data_index[0], parsing_key[0], State[0].next_stack);
    is_next_pair_at_depth1[0] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, depth1)(State[0].next_stack, data_fold[0]);

    is_key1_match_for_value[1] <== Mux1()([is_key1_match_for_value[0] * (1-is_next_pair_at_depth1[0]), is_key1_match[0] * (1-is_next_pair_at_depth1[0])], is_key1_match[0]);
    is_value_match[0] <== MultiAND(1)([is_key1_match_for_value[1]]);

    value_mask[0] <== data_fold[0] * parsing_value[0];
    mask[0] <== value_mask[0] * is_value_match[0];

    for(var data_idx = 1; data_idx < PER_FOLD_LENGTH; data_idx++) {
        State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data_fold[data_idx];
        State[data_idx].stack          <== State[data_idx - 1].next_stack;
        State[data_idx].parsing_string <== State[data_idx - 1].next_parsing_string;
        State[data_idx].parsing_number <== State[data_idx - 1].next_parsing_number;

        // - parsing key
        // - parsing value (different for string/numbers and array)
        // - key match (key 1, key 2)
        // - is next pair
        // - is key match for value
        // - value_mask
        // - mask

        // check if inside key or not
        parsing_key[data_idx] <== InsideKey(MAX_STACK_HEIGHT)(State[data_idx].next_stack, State[data_idx].next_parsing_string, State[data_idx].next_parsing_number);

        parsing_object1_value[data_idx] <== InsideValueAtDepth(MAX_STACK_HEIGHT, depth1)(State[data_idx].next_stack, State[data_idx].next_parsing_string, State[data_idx].next_parsing_number);
        // parsing correct value = AND(all individual stack values)
        parsing_value[data_idx] <== MultiAND(1)([parsing_object1_value[data_idx]]);

        // to get correct value, check:
        // - key matches at current index and depth of key is as specified
        // - whether next KV pair starts
        // - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
        data_index[data_idx] <== data_index[data_idx-1] + 1;
        is_key1_match[data_idx] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1)(data, key1, r, data_index[data_idx], parsing_key[data_idx], State[data_idx].next_stack);
        is_next_pair_at_depth1[data_idx] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, depth1)(State[data_idx].next_stack, data_fold[data_idx]);
        // pichla
        is_key1_match_for_value[data_idx+1] <== Mux1()([is_key1_match_for_value[data_idx] * (1-is_next_pair_at_depth1[data_idx]), is_key1_match[data_idx] * (1-is_next_pair_at_depth1[data_idx])], is_key1_match[data_idx]);
        is_value_match[data_idx] <== MultiAND(1)([is_key1_match_for_value[data_idx+1]]);


        // mask[i] = data[i] * parsing_value[i] * is_key_match_for_value[i]
        value_mask[data_idx] <== data_fold[data_idx] * parsing_value[data_idx];
        mask[data_idx] <== value_mask[data_idx] * is_value_match[data_idx];
        log("mask: ", data_idx, mask[data_idx]);
    }

    signal is_zero_mask[PER_FOLD_LENGTH];
    signal is_prev_starting_index[PER_FOLD_LENGTH];
    value_starting_index[0] <== step_in[MAX_STACK_HEIGHT*2 + 3];
    is_zero_mask[0] <== IsZero()(mask[0]);
    for (var i=1 ; i<PER_FOLD_LENGTH ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    signal output step_out[fold_input_len];
    for (var i=0 ; i<MAX_STACK_HEIGHT ; i++) {
        step_out[i*2] <== State[PER_FOLD_LENGTH-1].next_stack[i][0];
        step_out[i*2+1] <== State[PER_FOLD_LENGTH-1].next_stack[i][1];
        log("stack[", i, "]:", step_out[i*2], step_out[i*2+1]);
    }
    step_out[MAX_STACK_HEIGHT*2] <== State[PER_FOLD_LENGTH-1].next_parsing_string;
    step_out[MAX_STACK_HEIGHT*2 + 1] <== State[PER_FOLD_LENGTH-1].next_parsing_number;
    step_out[MAX_STACK_HEIGHT*2 + 2] <== is_key1_match_for_value[PER_FOLD_LENGTH];
    step_out[MAX_STACK_HEIGHT*2 + 3] <== value_starting_index[PER_FOLD_LENGTH-1] + PER_FOLD_LENGTH * step_in[MAX_STACK_HEIGHT*2 + 4];
    step_out[MAX_STACK_HEIGHT*2 + 4] <== step_in[MAX_STACK_HEIGHT*2 + 4] + 1;
    log("step_out: ", step_out[MAX_STACK_HEIGHT*2], step_out[MAX_STACK_HEIGHT*2+1], step_out[MAX_STACK_HEIGHT*2+2], step_out[MAX_STACK_HEIGHT*2+3], step_out[MAX_STACK_HEIGHT*2+4]);
}

// template ExtractStringValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen) {
//     signal input data[DATA_BYTES];

//     signal input key1[keyLen1];

//     signal output value[maxValueLen];

//     signal value_starting_index[DATA_BYTES];
//     value_starting_index <== ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen)(data, key1);


//     value <== SelectSubArray(DATA_BYTES, maxValueLen)(data, value_starting_index[DATA_BYTES-2]+1, maxValueLen);
// }

component main { public [step_in] } = ExtractValue(40, 10, 2, 4, 0, 3);