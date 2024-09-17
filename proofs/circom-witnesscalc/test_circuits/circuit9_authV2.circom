pragma circom 2.1.1;

include "../test_deps/iden3-circuits-authV2/circuits/auth/authV2.circom";

component main {public [challenge, gistRoot]} = AuthV2(40, 64);
