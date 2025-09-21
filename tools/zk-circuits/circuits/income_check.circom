pragma circom 2.1.6;
include "poseidon.circom";
include "comparators.circom";
include "mux2.circom";

// Income >= threshold with Merkle inclusion

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

template IncomeCheck(depth) {
    // Private inputs
    signal input valueField; // income as integer in field
    signal input salt;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Public inputs
    signal input root;
    signal input minIncome; // public threshold

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

    // Constraint: valueField >= minIncome => assert NOT(valueField < minIncome)
    component lt = LessThan(32);
    lt.in[0] <== valueField;
    lt.in[1] <== minIncome;
    lt.out === 0;
}

component main = IncomeCheck(20);
