// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title OfflineVerificationUtils
 * @notice Utility library for offline credential verification
 */
library OfflineVerificationUtils {
    struct OfflineCredential {
        address holder;
        string credentialType;
        bytes32 dataHash;
        uint256 issuedAt;
        uint256 expiresAt;
        address issuer;
        bytes signature;
    }

    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address signer) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        return ecrecover(hash, v, r, s);
    }

    function getCredentialHash(
        OfflineCredential memory credential
    ) internal pure returns (bytes32 hash) {
        return
            keccak256(
                abi.encode(
                    credential.holder,
                    credential.credentialType,
                    credential.dataHash,
                    credential.issuedAt,
                    credential.expiresAt,
                    credential.issuer
                )
            );
    }
}
