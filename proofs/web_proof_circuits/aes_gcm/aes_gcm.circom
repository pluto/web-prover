pragma circom 2.1.9;

include "aes-proof/circuits/aes-gcm/aes-gcm-foldable.circom";
include "aes-proof/circuits/aes-gcm/utils.circom";

// TODO(WJ 2024-10-29): We need to meet about our build pipeline so we can do better version control on our circuits. 
// Compute AES-GCM 
template AESGCMFOLD(INPUT_LEN) {
    assert(INPUT_LEN % 16 == 0);

    var DATA_BYTES = (INPUT_LEN * 2) + 5;

    signal input key[16];
    signal input iv[12];
    signal input aad[16];
    signal input plainText[16];

    // step_in[0..INPUT_LEN] => accumulate plaintext blocks
    // step_in[INPUT_LEN..INPUT_LEN*2]  => accumulate ciphertext blocks
    // step_in[INPUT_LEN*2..INPUT_LEN*2+4]  => lastCounter
    // Note: the below todo is addressed in: https://github.com/pluto/aes-proof/pull/105
    // step_in[INPUT_LEN*2+5]     => foldedBlocks // TODO(WJ 2024-10-24): technically not needed if can read 4 bytes as a 32 bit number
    signal input step_in[DATA_BYTES]; 
    signal output step_out[DATA_BYTES];
    signal counter <== step_in[INPUT_LEN*2 + 4];

    // write new plain text block.
    signal plainTextAccumulator[DATA_BYTES];    
    component writeToIndex = WriteToIndex(DATA_BYTES, 16);
    writeToIndex.array_to_write_to <== step_in;
    writeToIndex.array_to_write_at_index <== plainText;
    writeToIndex.index <== counter * 16;
    writeToIndex.out ==> plainTextAccumulator;

    // folds one block
    component aes = AESGCMFOLDABLE();
    aes.key       <== key;
    aes.iv        <== iv;
    aes.aad       <== aad;
    aes.plainText <== plainText;

    for(var i = 0; i < 4; i++) {
        aes.lastCounter[i] <== step_in[INPUT_LEN*2 + i];
    }

    // accumulate cipher text
    signal cipherTextAccumulator[DATA_BYTES];
    component writeCipherText = WriteToIndex(DATA_BYTES, 16);
    writeCipherText.array_to_write_to <== plainTextAccumulator;
    writeCipherText.array_to_write_at_index <== aes.cipherText;
    writeCipherText.index <== INPUT_LEN + counter * 16;
    writeCipherText.out ==> cipherTextAccumulator;

    // get counter
    signal counterAccumulator[DATA_BYTES];
    component writeCounter = WriteToIndex(DATA_BYTES, 4);
    writeCounter.array_to_write_to <== cipherTextAccumulator;
    writeCounter.array_to_write_at_index <== aes.counter;
    writeCounter.index <== INPUT_LEN*2;
    writeCounter.out ==> counterAccumulator;

    // accumulate number of folded blocks
    component writeNumberOfFoldedBlocks = WriteToIndex(DATA_BYTES, 1);
    writeNumberOfFoldedBlocks.array_to_write_to <== counterAccumulator;
    writeNumberOfFoldedBlocks.array_to_write_at_index <== [step_in[INPUT_LEN*2 + 4] + 1];
    writeNumberOfFoldedBlocks.index <== INPUT_LEN*2 + 4;
    writeNumberOfFoldedBlocks.out ==> step_out;
}

component main { public [step_in] } = AESGCMFOLD(64);