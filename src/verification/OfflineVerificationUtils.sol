// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title OfflineVerificationUtils
 * @notice Utility library for offline credential verification
 * @dev Provides helper functions for client applications to verify credentials
 *      without requiring blockchain connectivity
 */
library OfflineVerificationUtils {
    struct VerificationContext {
        bytes32 domainSeparator; // EIP-712 domain separator
        address[] trustedIssuers; // List of trusted issuer addresses
        mapping(bytes32 => bool) revokedCredentials; // Revoked credential hashes
        uint256 maxClockSkew; // Maximum acceptable time difference
        bool strictTimeValidation; // Whether to enforce strict time validation
    }

    struct OfflineCredential {
        address holder;
        string credentialType;
        bytes32 dataHash;
        uint256 issuedAt;
        uint256 expiresAt;
        uint256 nonce;
        address issuer;
        bytes signature;
    }

    struct ValidationResult {
        bool isValid;
        uint256 confidence; // Confidence level 0-100
        string[] warnings; // Non-fatal issues
        string errorMessage; // Fatal error if isValid = false
        uint256 validatedAt; // When validation was performed
    }

    // Error codes for different validation failures
    uint256 constant ERROR_INVALID_SIGNATURE = 1;
    uint256 constant ERROR_EXPIRED = 2;
    uint256 constant ERROR_NOT_YET_VALID = 3;
    uint256 constant ERROR_REVOKED = 4;
    uint256 constant ERROR_UNTRUSTED_ISSUER = 5;
    uint256 constant ERROR_INVALID_FORMAT = 6;

    /**
     * @dev Validates an offline credential with comprehensive checks
     * @param credential The credential to validate
     * @param context Verification context with trusted issuers, etc.
     * @return result Detailed validation result
     */
    function validateCredential(OfflineCredential memory credential, VerificationContext storage context)
        internal
        view
        returns (ValidationResult memory result)
    {
        result.validatedAt = block.timestamp;
        result.warnings = new string[](0);

        // Basic format validation
        if (credential.holder == address(0)) {
            result.isValid = false;
            result.errorMessage = "Invalid holder address";
            return result;
        }

        if (bytes(credential.credentialType).length == 0) {
            result.isValid = false;
            result.errorMessage = "Empty credential type";
            return result;
        }

        if (credential.signature.length == 0) {
            result.isValid = false;
            result.errorMessage = "Missing signature";
            return result;
        }

        // Time-based validation
        if (context.strictTimeValidation) {
            if (credential.issuedAt > block.timestamp + context.maxClockSkew) {
                result.isValid = false;
                result.errorMessage = "Credential issued in future";
                return result;
            }
        }

        if (credential.expiresAt > 0 && block.timestamp > credential.expiresAt) {
            result.isValid = false;
            result.errorMessage = "Credential expired";
            return result;
        }

        // Check if credential is revoked
        bytes32 credentialHash = getCredentialHash(credential);
        if (context.revokedCredentials[credentialHash]) {
            result.isValid = false;
            result.errorMessage = "Credential revoked";
            return result;
        }

        // Verify issuer is trusted
        bool issuerTrusted = false;
        for (uint256 i = 0; i < context.trustedIssuers.length; i++) {
            if (context.trustedIssuers[i] == credential.issuer) {
                issuerTrusted = true;
                break;
            }
        }

        if (!issuerTrusted) {
            result.isValid = false;
            result.errorMessage = "Issuer not trusted";
            return result;
        }

        // Verify cryptographic signature
        bool signatureValid = verifyCredentialSignature(credential, context.domainSeparator);
        if (!signatureValid) {
            result.isValid = false;
            result.errorMessage = "Invalid signature";
            return result;
        }

        // Calculate confidence based on various factors
        result.confidence = calculateConfidence(credential, context);
        result.isValid = true;
    }

    /**
     * @dev Verifies the cryptographic signature of a credential
     * @param credential The credential to verify
     * @param domainSeparator EIP-712 domain separator
     * @return isValid Whether signature is valid
     */
    function verifyCredentialSignature(OfflineCredential memory credential, bytes32 domainSeparator)
        internal
        pure
        returns (bool isValid)
    {
        bytes32 credentialTypeHash = keccak256(
            "OfflineCredential(address holder,string credentialType,bytes32 dataHash,uint256 issuedAt,uint256 expiresAt,uint256 nonce,address issuer)"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                credentialTypeHash,
                credential.holder,
                keccak256(bytes(credential.credentialType)),
                credential.dataHash,
                credential.issuedAt,
                credential.expiresAt,
                credential.nonce,
                credential.issuer
            )
        );

        bytes32 hash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        // Recover signer from signature
        address recoveredSigner = recoverSigner(hash, credential.signature);
        return recoveredSigner == credential.issuer;
    }

    /**
     * @dev Calculates confidence level for a credential
     * @param credential The credential to evaluate
     * @param context Verification context
     * @return confidence Confidence level 0-100
     */
    function calculateConfidence(OfflineCredential memory credential, VerificationContext storage context)
        internal
        view
        returns (uint256 confidence)
    {
        confidence = 100; // Start with full confidence

        // Reduce confidence based on age
        uint256 age = block.timestamp - credential.issuedAt;
        uint256 maxAge = 365 days; // 1 year

        if (age > maxAge) {
            confidence = (confidence * 70) / 100; // Reduce to 70%
        } else if (age > maxAge / 2) {
            confidence = (confidence * 85) / 100; // Reduce to 85%
        }

        // Reduce confidence if near expiry
        if (credential.expiresAt > 0) {
            uint256 timeToExpiry = credential.expiresAt > block.timestamp ? credential.expiresAt - block.timestamp : 0;
            uint256 totalValidPeriod = credential.expiresAt - credential.issuedAt;

            if (timeToExpiry < totalValidPeriod / 10) {
                // Less than 10% of valid period left
                confidence = (confidence * 80) / 100;
            }
        }

        // Adjust based on issuer reputation (placeholder - could be enhanced)
        // This could integrate with a reputation system

        return confidence;
    }

    /**
     * @dev Recovers signer address from hash and signature
     * @param hash The hash that was signed
     * @param signature The signature
     * @return signer The address that created the signature
     */
    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address signer) {
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

    /**
     * @dev Generates hash for a credential (for revocation checks)
     * @param credential The credential
     * @return hash The credential hash
     */
    function getCredentialHash(OfflineCredential memory credential) internal pure returns (bytes32 hash) {
        return keccak256(
            abi.encode(
                credential.holder,
                credential.credentialType,
                credential.dataHash,
                credential.issuedAt,
                credential.nonce,
                credential.issuer
            )
        );
    }

    /**
     * @dev Validates multiple credentials in batch
     * @param credentials Array of credentials to validate
     * @param context Verification context
     * @return results Array of validation results
     */
    function batchValidateCredentials(OfflineCredential[] memory credentials, VerificationContext storage context)
        internal
        view
        returns (ValidationResult[] memory results)
    {
        results = new ValidationResult[](credentials.length);

        for (uint256 i = 0; i < credentials.length; i++) {
            results[i] = validateCredential(credentials[i], context);
        }
    }

    /**
     * @dev Extracts credential data for display purposes
     * @param credential The credential
     * @return summary Human readable summary
     */
    function getCredentialSummary(OfflineCredential memory credential) internal view returns (string memory summary) {
        return string(
            abi.encodePacked(
                "Type: ",
                credential.credentialType,
                ", Holder: ",
                addressToString(credential.holder),
                ", Issued: ",
                uint256ToString(credential.issuedAt),
                ", Expires: ",
                credential.expiresAt > 0 ? uint256ToString(credential.expiresAt) : "Never",
                ", Issuer: ",
                addressToString(credential.issuer)
            )
        );
    }

    // Helper functions for string conversion
    function addressToString(address addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    function uint256ToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
