pragma circom 2.1.9;

include "aes-proof/circuits/aes-gcm/aes-gcm-foldable.circom";
include "aes-proof/circuits/aes-gcm/utils.circom";
include "@zk-email/circuits/utils/array.circom";


template AESGCMFOLD(bytesPerFold, totalBytes, inputBytes) {
    // cannot fold outside chunk boundaries.
    assert(bytesPerFold % 16 == 0);
    assert(totalBytes % 16 == 0);

    signal input key[16];
    signal input iv[12];
    signal input aad[16];
    signal input plainText[bytesPerFold];
    signal input cipherText[totalBytes];

    // Output from the last encryption step
    // Always use last bytes for inputs which are not same size.
    // step_in[0..16] => lastCounter
    // step_in[16..32] => lastTag
    // step_in[32..48] => foldedBlocks
    // step_in[48] => plainText matching
    // step_in[49] => cipherText matching
    signal input step_in[inputBytes];

    // For now, attempt to support variable fold size. Potential fix at 16 in the future.
    component aes = AESGCMFOLDABLE(bytesPerFold, totalBytes\16);
    aes.key <== key;
    aes.iv <== iv;
    aes.aad <== aad;
    aes.plainText <== plainText;

    // Fold inputs
    var inputIndex = bytesPerFold-4;
    for(var i = 0; i < 4; i++) {
        aes.lastCounter[i] <== step_in[inputIndex];
        inputIndex+=1;
    }

    for(var i = 0; i < 16; i++) {
        aes.lastTag[i] <== step_in[inputIndex];
        inputIndex+=1;
    }
    // TODO: range check, assertions, stuff.
    inputIndex+=15;
    aes.foldedBlocks <== step_in[inputIndex];

    // Fold Outputs
    signal output step_out[inputBytes];
    var outputIndex = bytesPerFold-4;
    for(var i = 0; i < 4; i++) {
        step_out[outputIndex] <== aes.counter[i];
        outputIndex+=1;
    }
    for(var i = 0; i < 16; i++) {
        step_out[outputIndex] <== aes.authTag[i];
        outputIndex+=1;
    }
    outputIndex+=15;
    step_out[outputIndex] <== step_in[inputIndex] + bytesPerFold \ 16;

    // check plaintext and ciphertext match
    signal plainTextCheckIndex <== 48 + ((step_in[15] - 1) * bytesPerFold);
    signal plainTextBlock[bytesPerFold] <== SelectSubArray(inputBytes, bytesPerFold)(step_in, plainTextCheckIndex, bytesPerFold);
    signal isPlainTextMatch <== IsEqualArray(bytesPerFold)([plainText, plainTextBlock]);
    step_out[48] <== step_in[48] * isPlainTextMatch;

    signal cipherTextCheckIndex <== (step_in[15] - 1) * bytesPerFold;
    signal cipherTextBlock[bytesPerFold] <== SelectSubArray(totalBytes, bytesPerFold)(cipherText, cipherTextCheckIndex, bytesPerFold);
    signal isCipherTextMatch <== IsEqualArray(bytesPerFold)([aes.cipherText, cipherTextBlock]);
    step_out[49] <== step_in[49] * isCipherTextMatch;

    for(var i = 50 ; i < inputBytes ; i++) {
        step_out[i] <== step_in[i];
    }
}

component main { public [step_in] } = AESGCMFOLD(16, 320, 4000);