// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./OfflineVerificationManager.sol";
import "../libs/OfflineVerificationUtils.sol";

/**
 * @title MobileVerificationInterface
 * @notice Mobile-friendly interface for offline credential verification
 * @dev Optimized for mobile apps, QR codes, and NFC verification
 */
contract MobileVerificationInterface {
    using OfflineVerificationUtils for OfflineVerificationUtils.OfflineCredential;

    OfflineVerificationManager public verificationManager;

    struct MobileCredential {
        address holder;
        string credentialType;
        string displayName; // Human readable name
        string description; // Credential description
        bytes32 dataHash;
        uint256 issuedAt;
        uint256 expiresAt;
        address issuer;
        string issuerName; // Human readable issuer name
        bytes signature;
        string qrCodeData; // Base64 encoded QR data
        uint8 version; // Format version for compatibility
    }

    struct VerificationResponse {
        bool isValid;
        string status; // "VALID", "EXPIRED", "REVOKED", "INVALID"
        uint256 confidence; // 0-100
        string holderInfo; // Masked holder information for privacy
        string credentialInfo; // Human readable credential info
        uint256 verifiedAt;
        string[] warnings; // Any warnings about the credential
    }

    // Events for mobile verification tracking
    event MobileVerificationPerformed(
        address indexed verifier,
        bytes32 indexed credentialHash,
        bool isValid,
        string status,
        uint256 timestamp
    );

    event QRCodeGenerated(
        address indexed holder,
        string credentialType,
        string qrCodeData,
        uint256 expiresAt
    );

    constructor(address _verificationManager) {
        verificationManager = OfflineVerificationManager(_verificationManager);
    }

    /**
     * @dev Verifies a credential from QR code data
     * @param qrData Base64 encoded QR code data
     * @return response Verification response with user-friendly information
     */
    function verifyFromQR(
        bytes memory qrData
    ) external returns (VerificationResponse memory response) {
        // Decode QR data to credential
        OfflineVerificationManager.OfflineCredential
            memory credential = _decodeQRData(qrData);

        // Perform verification
        (bool isValid, string memory reason) = verificationManager
            .verifyOfflineCredential(credential);

        response = VerificationResponse({
            isValid: isValid,
            status: isValid ? "VALID" : "INVALID",
            confidence: isValid ? 95 : 0, // Simplified confidence calculation
            holderInfo: _getMaskedAddress(credential.holder),
            credentialInfo: _formatCredentialInfo(credential),
            verifiedAt: block.timestamp,
            warnings: new string[](0)
        });

        if (!isValid) {
            response.status = _getStatusFromReason(reason);
        }

        // Add warnings for near-expiry credentials
        if (isValid && credential.expiresAt > 0) {
            uint256 timeToExpiry = credential.expiresAt - block.timestamp;
            if (timeToExpiry < 7 days && timeToExpiry > 0) {
                response.warnings = new string[](1);
                response.warnings[0] = "Credential expires within 7 days";
                response.confidence = 85;
            }
        }

        emit MobileVerificationPerformed(
            msg.sender,
            _getCredentialHash(credential),
            isValid,
            response.status,
            block.timestamp
        );
    }

    /**
     * @dev Generates mobile-friendly credential data with QR code
     * @param credential Base credential data
     * @param displayName Human readable name for the credential
     * @param description Description of the credential
     * @return mobileCredential Enhanced credential with mobile-friendly data
     */
    function createMobileCredential(
        OfflineVerificationManager.OfflineCredential memory credential,
        string memory displayName,
        string memory description
    ) external returns (MobileCredential memory mobileCredential) {
        // Get issuer name (simplified - in production, this would be a registry lookup)
        string memory issuerName = _getIssuerName(credential.issuer);

        // Generate QR code data
        bytes memory qrCodeData = verificationManager.generateQRData(
            credential
        );

        mobileCredential = MobileCredential({
            holder: credential.holder,
            credentialType: credential.credentialType,
            displayName: displayName,
            description: description,
            dataHash: credential.dataHash,
            issuedAt: credential.issuedAt,
            expiresAt: credential.expiresAt,
            issuer: credential.issuer,
            issuerName: issuerName,
            signature: credential.signature,
            qrCodeData: _bytesToBase64(qrCodeData),
            version: 1
        });

        emit QRCodeGenerated(
            credential.holder,
            credential.credentialType,
            mobileCredential.qrCodeData,
            credential.expiresAt
        );
    }

    /**
     * @dev Quick verification for NFC tap scenarios
     * @param credentialHash Hash of the credential for quick lookup
     * @return isValid Simple boolean result for fast verification
     * @return statusCode Numeric status code for mobile apps
     */
    function quickVerify(
        bytes32 credentialHash
    ) external view returns (bool isValid, uint8 statusCode) {
        // Check if revoked
        if (verificationManager.isCredentialRevoked(credentialHash)) {
            return (false, 2); // Status code 2 = REVOKED
        }

        // For a full quick verify, we'd need to store credential data
        // This is a simplified version
        return (true, 1); // Status code 1 = VALID
    }

    /**
     * @dev Batch verification for multiple credentials
     * @param qrDataArray Array of QR code data
     * @return responses Array of verification responses
     */
    function batchVerifyFromQR(
        bytes[] memory qrDataArray
    ) external view returns (VerificationResponse[] memory responses) {
        responses = new VerificationResponse[](qrDataArray.length);

        for (uint256 i = 0; i < qrDataArray.length; i++) {
            responses[i] = _verifyFromQRInternal(qrDataArray[i]);
        }
    }

    /**
     * @dev Get verification statistics for analytics
     * @param credentialHash Hash of credential to get stats for
     * @return verificationCount Number of times verified
     * @return lastVerified Timestamp of last verification
     */
    function getVerificationStats(
        bytes32 credentialHash
    ) external view returns (uint256 verificationCount, uint256 lastVerified) {
        // In a full implementation, this would track verification events
        // For now, return placeholder values
        return (0, 0);
    }

    // Internal helper functions
    function _verifyFromQRInternal(
        bytes memory qrData
    ) internal view returns (VerificationResponse memory response) {
        // Decode QR data to credential
        OfflineVerificationManager.OfflineCredential
            memory credential = _decodeQRData(qrData);

        // Perform verification
        (bool isValid, string memory reason) = verificationManager
            .verifyOfflineCredential(credential);

        response = VerificationResponse({
            isValid: isValid,
            status: isValid ? "VALID" : "INVALID",
            confidence: isValid ? 95 : 0, // Simplified confidence calculation
            holderInfo: _getMaskedAddress(credential.holder),
            credentialInfo: _formatCredentialInfo(credential),
            verifiedAt: block.timestamp,
            warnings: new string[](0)
        });

        if (!isValid) {
            response.status = _getStatusFromReason(reason);
        }

        // Add warnings for near-expiry credentials
        if (isValid && credential.expiresAt > 0) {
            uint256 timeToExpiry = credential.expiresAt - block.timestamp;
            if (timeToExpiry < 7 days && timeToExpiry > 0) {
                response.warnings = new string[](1);
                response.warnings[0] = "Credential expires within 7 days";
                response.confidence = 85;
            }
        }
    }

    function _decodeQRData(
        bytes memory qrData
    )
        internal
        pure
        returns (OfflineVerificationManager.OfflineCredential memory credential)
    {
        // Decode the QR data back to credential structure
        (
            credential.holder,
            credential.credentialType,
            credential.dataHash,
            credential.issuedAt,
            credential.expiresAt,
            credential.signature
        ) = abi.decode(
            qrData,
            (address, string, bytes32, uint256, uint256, bytes)
        );

        // Note: In production, the issuer and nonce would also be encoded
        // This is simplified for demonstration
    }

    function _getMaskedAddress(
        address addr
    ) internal pure returns (string memory) {
        string memory addrStr = _addressToString(addr);
        // Return first 6 and last 4 characters with dots in between
        bytes memory masked = abi.encodePacked(
            _substring(addrStr, 0, 6),
            "...",
            _substring(addrStr, 38, 42)
        );
        return string(masked);
    }

    function _formatCredentialInfo(
        OfflineVerificationManager.OfflineCredential memory credential
    ) internal view returns (string memory) {
        string memory issuerName = _getIssuerName(credential.issuer);
        return
            string(
                abi.encodePacked(
                    credential.credentialType,
                    " issued by ",
                    issuerName,
                    credential.expiresAt > 0
                        ? string(
                            abi.encodePacked(
                                " (expires ",
                                _timestampToDate(credential.expiresAt),
                                ")"
                            )
                        )
                        : " (no expiry)"
                )
            );
    }

    function _getStatusFromReason(
        string memory reason
    ) internal pure returns (string memory) {
        bytes32 reasonHash = keccak256(bytes(reason));

        if (reasonHash == keccak256("Credential expired")) {
            return "EXPIRED";
        } else if (reasonHash == keccak256("Credential revoked")) {
            return "REVOKED";
        } else if (reasonHash == keccak256("Invalid signature")) {
            return "INVALID_SIGNATURE";
        } else if (reasonHash == keccak256("Issuer not trusted")) {
            return "UNTRUSTED_ISSUER";
        }

        return "INVALID";
    }

    function _getIssuerName(
        address issuer
    ) internal view returns (string memory) {
        // In production, this would lookup issuer names from a registry
        // For now, return a shortened address
        return _getMaskedAddress(issuer);
    }

    function _getCredentialHash(
        OfflineVerificationManager.OfflineCredential memory credential
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    credential.holder,
                    credential.credentialType,
                    credential.dataHash,
                    credential.issuedAt,
                    credential.issuer
                )
            );
    }

    function _bytesToBase64(
        bytes memory data
    ) internal pure returns (string memory) {
        // Simplified base64 encoding - in production use a proper library
        return "BASE64_ENCODED_DATA";
    }

    function _addressToString(
        address addr
    ) internal pure returns (string memory) {
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

    function _substring(
        string memory str,
        uint256 startIndex,
        uint256 endIndex
    ) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(endIndex - startIndex);
        for (uint256 i = startIndex; i < endIndex; i++) {
            result[i - startIndex] = strBytes[i];
        }
        return string(result);
    }

    function _timestampToDate(
        uint256 timestamp
    ) internal pure returns (string memory) {
        // Simplified date formatting - in production use a proper date library
        return string(abi.encodePacked("Timestamp: ", _uint2str(timestamp)));
    }

    function _uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - (_i / 10) * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
}
