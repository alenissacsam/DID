pragma circom 2.1.6;
include "poseidon.circom";
include "comparators.circom";
include "mux2.circom";

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

template AgeMaxCheck(depth) {
    // Private
    signal input valueField; // birthYear
    signal input salt;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Public
    signal input root;
    signal input maxAge;   // user asserts they are <= maxAge
    signal input nowYear;

    // Leaf
    component leafPoseidon = Poseidon(2);
    leafPoseidon.inputs[0] <== valueField;
    leafPoseidon.inputs[1] <== salt;
    signal leaf;
    leaf <== leafPoseidon.out;

    // Merkle
    component mp = MerkleInclusion(depth);
    mp.leaf <== leaf;
    for (var i = 0; i < depth; i++) {
        mp.pathElements[i] <== pathElements[i];
        mp.pathIndices[i] <== pathIndices[i];
    }
    mp.root <== root;

    // Constraint: nowYear - birthYear <= maxAge
    signal birthYear;
    birthYear <== valueField;
    signal age;
    age <== nowYear - birthYear;
    // Enforce age <= maxAge => assert NOT(maxAge < age)
    component lt = LessThan(16);
    lt.in[0] <== maxAge;  // a
    lt.in[1] <== age;     // b
    lt.out === 0;         // a < b must be false
}

component main = AgeMaxCheck(20);
