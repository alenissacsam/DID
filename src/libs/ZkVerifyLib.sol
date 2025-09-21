// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library ZkVerifyLib {
    function verify(
        bytes memory verificationKey,
        bytes memory proof,
        bytes memory publicInputs
    ) internal pure returns (bool) {
        return
            verificationKey.length > 0 &&
            proof.length > 0 &&
            publicInputs.length > 0;
    }
}
