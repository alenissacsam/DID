pragma circom 2.1.6;
include "poseidon.circom";
include "comparators.circom";
include "mux2.circom";

// Simple Poseidon-based Merkle inclusion proof
// Assumes Poseidon hash and a fixed DEPTH (set via template parameter)

template MerkleInclusion(depth) {
    signal input leaf;                 // Poseidon(value, salt)
    signal input pathElements[depth];  // sibling nodes
    signal input pathIndices[depth];   // 0/1 for left/right
    signal input root;                 // public root

    // Working state per level
    signal cur[depth + 1];
    cur[0] <== leaf;

    component hashers[depth];
    signal piBits[depth];
    component muxL[depth];
    component muxR[depth];

    for (var i = 0; i < depth; i++) {
        // Constrain pathIndices to {0,1}
        piBits[i] <== pathIndices[i];
        piBits[i] * (piBits[i] - 1) === 0;

        // Use Mux2 with selector s[0]=piBits[i], s[1]=0
        muxL[i] = Mux2();
        muxR[i] = Mux2();
        // Left selects between cur[i] (when pi=0) and pathElements[i] (when pi=1)
        muxL[i].c[0] <== cur[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].c[2] <== cur[i];
        muxL[i].c[3] <== pathElements[i];
        muxL[i].s[0] <== piBits[i];
        muxL[i].s[1] <== 0;

        // Right selects opposite: pathElements when pi=0, cur when pi=1
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

    // Check final root
    cur[depth] === root;
}

template AgeCheck(depth) {
    // Private inputs
    signal input valueField; // packed DOB timestamp (or birth year), encoded as field
    signal input salt;       // random
    signal input pathElements[depth];
    signal input pathIndices[depth];

    // Public inputs
    signal input root;       // merkle root
    signal input minAge;     // required minimum age in years
    signal input nowYear;    // current year (public)

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

    // Age policy: nowYear - birthYear >= minAge
    // For simplicity, we encode valueField as an integer birthYear
    signal birthYear;
    birthYear <== valueField;

    signal age;
    age <== nowYear - birthYear;

    // Enforce age >= minAge using comparator: assert NOT(age < minAge)
    component lt = LessThan(16);
    lt.in[0] <== age;      // a
    lt.in[1] <== minAge;   // b
    lt.out === 0;          // a < b must be false
}

// Default main with Merkle depth 20
component main = AgeCheck(20);
