pragma circom 2.1.6;
include "poseidon.circom";
include "mux2.circom";

// Equality proof for a generic attribute committed as leaf = Poseidon(valueField, salt)
// Also verifies inclusion in a Poseidon Merkle root

template MerkleInclusion(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    signal cur[depth + 1];
    cur[0] <== leaf;

    component hashers[depth];
    signal piBits[depth];
    component muxL[depth];
    component muxR[depth];

    for (var i = 0; i < depth; i++) {
        piBits[i] <== pathIndices[i];
        piBits[i] * (piBits[i] - 1) === 0;

        muxL[i] = Mux2();
        muxR[i] = Mux2();
        muxL[i].c[0] <== cur[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].c[2] <== cur[i];
        muxL[i].c[3] <== pathElements[i];
        muxL[i].s[0] <== piBits[i];
        muxL[i].s[1] <== 0;

        muxR[i].c[0] <== pathElements[i];
        muxR[i].c[1] <== cur[i];
        muxR[i].c[2] <== pathElements[i];
        muxR[i].c[3] <== cur[i];
        muxR[i].s[0] <== piBits[i];
        muxR[i].s[1] <== 0;

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxL[i].out;
        hashers[i].inputs[1] <== muxR[i].out;
        cur[i+1] <== hashers[i].out;
    }

    cur[depth] === root;
}

template AttrEquals(depth) {
    // Private inputs
    signal input valueField; // packed ASCII for the attribute (e.g., name or DOB string)
    signal input salt;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Public inputs
    signal input root;   // Poseidon Merkle root
    signal input target; // expected valueField (public)

    // Recompute leaf
    component leafPoseidon = Poseidon(2);
    leafPoseidon.inputs[0] <== valueField;
    leafPoseidon.inputs[1] <== salt;
    signal leaf;
    leaf <== leafPoseidon.out;

    // Merkle proof
    component mp = MerkleInclusion(depth);
    mp.leaf <== leaf;
    for (var i = 0; i < depth; i++) {
        mp.pathElements[i] <== pathElements[i];
        mp.pathIndices[i] <== pathIndices[i];
    }
    mp.root <== root;

    // Equality constraint
    valueField === target;
}

component main = AttrEquals(20);
