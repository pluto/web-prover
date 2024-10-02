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

template ExtractValue(DATA_BYTES, CHUNK_LENGTH, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen) {
    // stack, parsing_string, parsing_number, is_key1_match_for_value, value_starting_index, curr_fold_index, value_first_chunk, value
    var fold_input_len = MAX_STACK_HEIGHT*2 + 6 + maxValueLen;
    signal input step_in[fold_input_len];

    // curr chunk index
    signal curr_fold_index <== step_in[MAX_STACK_HEIGHT*2 + 4];
    // chunk index when first value byte appears
    signal value_first_chunk_index <== step_in[MAX_STACK_HEIGHT*2 + 5];

    // original data
    signal input data[DATA_BYTES];
    // data folded input
    signal input data_fold[CHUNK_LENGTH];
    // key
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
    // signal CURR_FOLD_INDEX <== curr_fold_index;

    // value mask
    signal mask[CHUNK_LENGTH];
    // starting index of value in `data`
    signal value_starting_index[CHUNK_LENGTH];

    // current data index as per chunk length
    signal data_index[CHUNK_LENGTH];
    data_index[0] <== curr_fold_index * CHUNK_LENGTH;

    component State[CHUNK_LENGTH];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data_fold[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [step_in[i*2], step_in[i*2+1]];
    }
    State[0].parsing_string <== step_in[MAX_STACK_HEIGHT*2];
    State[0].parsing_number <== step_in[MAX_STACK_HEIGHT*2 + 1];


    // parse first byte separately to initialise all the other signals required to calculate value index
    signal parsing_key[CHUNK_LENGTH];
    signal parsing_value[CHUNK_LENGTH];
    signal parsing_object1_value[CHUNK_LENGTH];
    signal is_key1_match[CHUNK_LENGTH];
    signal is_key1_match_for_value[CHUNK_LENGTH+1];
    is_key1_match_for_value[0] <== step_in[MAX_STACK_HEIGHT*2 + 2];
    signal is_next_pair_at_depth1[CHUNK_LENGTH];

    signal is_value_match[CHUNK_LENGTH];
    signal value_mask[CHUNK_LENGTH];

    parsing_key[0] <== InsideKey(MAX_STACK_HEIGHT)(State[0].next_stack, State[0].next_parsing_string, State[0].next_parsing_number);
    parsing_object1_value[0] <== InsideValueAtDepth(MAX_STACK_HEIGHT, depth1)(State[0].next_stack, State[0].next_parsing_string, State[0].next_parsing_number);
    parsing_value[0] <== MultiAND(1)([parsing_object1_value[0]]);


    is_key1_match[0] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1)(data, key1, r, data_index[0], parsing_key[0], State[0].next_stack);
    is_next_pair_at_depth1[0] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, depth1)(State[0].next_stack, data_fold[0]);

    is_key1_match_for_value[1] <== Mux1()([is_key1_match_for_value[0] * (1-is_next_pair_at_depth1[0]), is_key1_match[0] * (1-is_next_pair_at_depth1[0])], is_key1_match[0]);
    is_value_match[0] <== MultiAND(1)([is_key1_match_for_value[1]]);

    value_mask[0] <== data_fold[0] * parsing_value[0];
    mask[0] <== value_mask[0] * is_value_match[0];

    for(var data_idx = 1; data_idx < CHUNK_LENGTH; data_idx++) {
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
        is_key1_match_for_value[data_idx+1] <== Mux1()([is_key1_match_for_value[data_idx] * (1-is_next_pair_at_depth1[data_idx]), is_key1_match[data_idx] * (1-is_next_pair_at_depth1[data_idx])], is_key1_match[data_idx]);
        // log("is_key_match", is_key1_match_for_value[data_idx], is_next_pair_at_depth1[data_idx], is_key1_match[data_idx]);
        is_value_match[data_idx] <== MultiAND(1)([is_key1_match_for_value[data_idx+1]]);


        // mask[i] = data[i] * parsing_value[i] * is_key_match_for_value[i]
        value_mask[data_idx] <== data_fold[data_idx] * parsing_value[data_idx];
        mask[data_idx] <== value_mask[data_idx] * is_value_match[data_idx];
        // log("mask: ", mask[data_idx], parsing_value[data_idx], is_value_match[data_idx]);
        // log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }

    // checks if the mask is zero at an index to determine when the value starts
    signal is_zero_mask[CHUNK_LENGTH];
    // measures if previous index was the value starting index
    signal is_prev_starting_index[CHUNK_LENGTH];
    // measures if the value is inside this chunk
    signal is_value_inside_chunk[CHUNK_LENGTH];

    value_starting_index[0] <== step_in[MAX_STACK_HEIGHT*2 + 3];
    is_zero_mask[0] <== IsZero()(mask[0]);

    signal is_value_starting_at_index_zero <== IsZero()(value_starting_index[0]);
    is_value_inside_chunk[0] <== (1-is_zero_mask[0]) * is_value_starting_at_index_zero;

    for (var i=1 ; i<CHUNK_LENGTH ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        is_value_inside_chunk[i] <==  is_value_inside_chunk[i-1] + (1-is_zero_mask[i]) * is_prev_starting_index[i];
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }

    // add current fold output for next fold iteration
    signal output step_out[fold_input_len];

    // add new stack output
    for (var i=0 ; i<MAX_STACK_HEIGHT ; i++) {
        step_out[i*2] <== State[CHUNK_LENGTH-1].next_stack[i][0];
        step_out[i*2+1] <== State[CHUNK_LENGTH-1].next_stack[i][1];
        // log("stack[", i, "]:", step_out[i*2], step_out[i*2+1]);
    }
    step_out[MAX_STACK_HEIGHT*2] <== State[CHUNK_LENGTH-1].next_parsing_string;
    step_out[MAX_STACK_HEIGHT*2 + 1] <== State[CHUNK_LENGTH-1].next_parsing_number;

    // is key matched for the value being parsed with next fold
    step_out[MAX_STACK_HEIGHT*2 + 2] <== is_key1_match_for_value[CHUNK_LENGTH];

    // add fold length to value_starting_index if value found in this chunk is non-zero
    signal is_value_in_curr_chunk <== IsZero()(is_value_inside_chunk[CHUNK_LENGTH-1]);
    // is value found in any of the previous chunk
    signal is_value_not_found_in_previous_chunks <== IsZero()(value_first_chunk_index);
    // is value starting in current chunk
    signal is_value_starting_in_curr_chunk <== (1 - is_value_in_curr_chunk) * is_value_not_found_in_previous_chunks;
    // first chunk index where value starts
    signal value_first_chunk <== Mux1()([value_first_chunk_index, curr_fold_index], is_value_starting_in_curr_chunk);

    // determine whether to add previous chunk lengths
    signal whether_add_index <== IsZero()(is_value_starting_in_curr_chunk);
    // calculate index to add
    signal index_addition <== Mux1()([0, CHUNK_LENGTH * curr_fold_index], 1-whether_add_index);
    // calculate final value_starting_index
    step_out[MAX_STACK_HEIGHT*2 + 3] <== value_starting_index[CHUNK_LENGTH-1] + index_addition;

    // increment current fold index
    step_out[MAX_STACK_HEIGHT*2 + 4] <== curr_fold_index + 1;

    // value found in which chunk
    step_out[MAX_STACK_HEIGHT*2 + 5] <== value_first_chunk;

    // debug logs
    // log("step_out: ", step_out[MAX_STACK_HEIGHT*2], step_out[MAX_STACK_HEIGHT*2 + 1], step_out[MAX_STACK_HEIGHT*2 + 2], step_out[MAX_STACK_HEIGHT*2 + 3], step_out[MAX_STACK_HEIGHT*2 + 4], step_out[MAX_STACK_HEIGHT*2 + 5]);

    // shift value bytes and add to output if processing last chunk
    var last_chunk = DATA_BYTES/CHUNK_LENGTH;
    signal is_last_chunk <== IsEqual()([last_chunk, step_out[MAX_STACK_HEIGHT*2 + 4]]);

    signal tentative_value[maxValueLen];
    tentative_value <== SelectSubArray(DATA_BYTES, maxValueLen)(data, step_out[MAX_STACK_HEIGHT*2 + 3]+1, maxValueLen);
    signal value[maxValueLen];
    value <== ScalarArrayMul(maxValueLen)(tentative_value, is_last_chunk);

    for (var i=0 ; i<maxValueLen ; i++) {
        step_out[MAX_STACK_HEIGHT*2 + 6+i] <== value[i];
    }
}

component main { public [step_in] } = ExtractValue(60, 10, 1, 4, 0, 23);
