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

template ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen) {
    signal input data[DATA_BYTES];

    signal input key1[keyLen1];

    // r must be secret, so either has to be derived from hash in the circuit or off the circuit
    component rHasher = PoseidonModular(DATA_BYTES +  keyLen1);
    for (var i = 0 ; i < keyLen1 ; i++) {
        rHasher.in[i] <== key1[i];
    }
    for (var i = 0 ; i < DATA_BYTES ; i++) {
        rHasher.in[i + keyLen1] <== data[i];
    }
    signal r <== rHasher.out;

    signal output value_starting_index[DATA_BYTES];

    signal mask[DATA_BYTES];
    // mask[0] <== 0;

    var logDataLen = log2Ceil(DATA_BYTES);

    component State[DATA_BYTES];
    State[0] = StateUpdate(MAX_STACK_HEIGHT);
    State[0].byte           <== data[0];
    for(var i = 0; i < MAX_STACK_HEIGHT; i++) {
        State[0].stack[i]   <== [0,0];
    }
    State[0].parsing_string <== 0;
    State[0].parsing_number <== 0;

    signal parsing_key[DATA_BYTES];
    signal parsing_value[DATA_BYTES];
    signal parsing_object1_value[DATA_BYTES];
    signal is_key1_match[DATA_BYTES];
    signal is_key1_match_for_value[DATA_BYTES];
    is_key1_match_for_value[0] <== 0;
    signal is_next_pair_at_depth1[DATA_BYTES];

    signal is_value_match[DATA_BYTES];
    is_value_match[0] <== 0;
    signal value_mask[DATA_BYTES];
    for(var data_idx = 1; data_idx < DATA_BYTES; data_idx++) {
        State[data_idx]                  = StateUpdate(MAX_STACK_HEIGHT);
        State[data_idx].byte           <== data[data_idx];
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
        parsing_key[data_idx-1] <== InsideKey(MAX_STACK_HEIGHT)(State[data_idx].stack, State[data_idx].parsing_string, State[data_idx].parsing_number);

        parsing_object1_value[data_idx-1] <== InsideValueAtDepth(MAX_STACK_HEIGHT, depth1)(State[data_idx].stack, State[data_idx].parsing_string, State[data_idx].parsing_number);
        // parsing correct value = AND(all individual stack values)
        parsing_value[data_idx-1] <== MultiAND(1)([parsing_object1_value[data_idx-1]]);

        // to get correct value, check:
        // - key matches at current index and depth of key is as specified
        // - whether next KV pair starts
        // - whether key matched for a value (propogate key match until new KV pair of lower depth starts)
        is_key1_match[data_idx-1] <== KeyMatchAtDepth(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1)(data, key1, r, data_idx-1, parsing_key[data_idx-1], State[data_idx].stack);
        is_next_pair_at_depth1[data_idx-1] <== NextKVPairAtDepth(MAX_STACK_HEIGHT, depth1)(State[data_idx].stack, data[data_idx-1]);
        is_key1_match_for_value[data_idx] <== Mux1()([is_key1_match_for_value[data_idx-1] * (1-is_next_pair_at_depth1[data_idx-1]), is_key1_match[data_idx-1] * (1-is_next_pair_at_depth1[data_idx-1])], is_key1_match[data_idx-1]);
        is_value_match[data_idx] <== MultiAND(1)([is_key1_match_for_value[data_idx]]);


        // mask[i] = data[i] * parsing_value[i] * is_key_match_for_value[i]
        value_mask[data_idx-1] <== data[data_idx-1] * parsing_value[data_idx-1];
        mask[data_idx-1] <== value_mask[data_idx-1] * is_value_match[data_idx];
    }
    // signal value_starting_index[DATA_BYTES];
    signal is_zero_mask[DATA_BYTES];
    signal is_prev_starting_index[DATA_BYTES];
    value_starting_index[0] <== 0;
    is_zero_mask[0] <== IsZero()(mask[0]);
    for (var i=1 ; i<DATA_BYTES-1 ; i++) {
        is_zero_mask[i] <== IsZero()(mask[i]);
        is_prev_starting_index[i] <== IsZero()(value_starting_index[i-1]);
        value_starting_index[i] <== value_starting_index[i-1] + i * (1-is_zero_mask[i]) * is_prev_starting_index[i];
    }
}
template ExtractStringValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen) {
    signal input data[DATA_BYTES];

    signal input key1[keyLen1];

    signal output value[maxValueLen];

    signal value_starting_index[DATA_BYTES];
    value_starting_index <== ExtractValue(DATA_BYTES, MAX_STACK_HEIGHT, keyLen1, depth1, maxValueLen)(data, key1);

    
    value <== SelectSubArray(DATA_BYTES, maxValueLen)(data, value_starting_index[DATA_BYTES-2]+1, maxValueLen);
}
