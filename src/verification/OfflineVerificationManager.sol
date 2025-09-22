// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "../interfaces/IZkProofManager.sol";

/**
 * @title OfflineVerificationManager
 * @notice Manages cryptographic proofs for offline credential verification
 * @dev Implements multiple offline verification mechanisms:
 *      1. Signed certificates with expiry
 *      2. Merkle tree proofs for batch credentials
 *      3. Zero-knowledge proof integration
 *      4. QR code compatible verification data
 */
contract OfflineVerificationManager is AccessControl, EIP712 {
    using ECDSA for bytes32;

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    // EIP-712 Domain
    string private constant SIGNING_DOMAIN = "EduCert";
    string private constant SIGNATURE_VERSION = "1";

    // EIP-712 TypeHash for offline credentials
    bytes32 private constant CREDENTIAL_TYPEHASH =
        keccak256(
            "OfflineCredential(address holder,string credentialType,bytes32 dataHash,uint256 issuedAt,uint256 expiresAt,uint256 nonce,address issuer)"
        );

    struct OfflineCredential {
        address holder; // Credential holder address
        string credentialType; // Type of credential (e.g., "DEGREE", "CERTIFICATE")
        bytes32 dataHash; // Hash of credential data
        uint256 issuedAt; // Timestamp when issued
        uint256 expiresAt; // Expiration timestamp (0 = never expires)
        uint256 nonce; // Unique nonce for replay protection
        address issuer; // Address of the issuer
        bytes signature; // Issuer's signature
    }

    struct MerkleProof {
        bytes32[] proof; // Merkle proof path
        bytes32 root; // Merkle root
        uint256 leafIndex; // Index of the leaf in the tree
        uint256 batchId; // Batch identifier
    }

    struct OfflineVerificationPackage {
        OfflineCredential credential;
        MerkleProof merkleProof;
        bytes32[] additionalProofs; // For ZK or other proof systems
        uint256 packageVersion; // Version for compatibility
    }

    // Storage
    mapping(bytes32 => bool) public revokedCredentials;
    mapping(address => mapping(uint256 => bool)) public usedNonces;
    mapping(bytes32 => uint256) public merkleRoots; // root => timestamp when added
    mapping(address => bool) public trustedIssuers;
    mapping(string => uint256) public credentialTypeExpiry; // default expiry per type
    IZkProofManager public zkProofManager;

    uint256 public defaultCredentialExpiry = 365 days;
    uint256 public maxOfflineVerificationPeriod = 30 days;

    event CredentialIssued(
        address indexed holder,
        string credentialType,
        bytes32 indexed dataHash,
        uint256 expiresAt,
        address indexed issuer
    );

    event CredentialRevoked(
        bytes32 indexed credentialHash,
        address indexed revoker,
        string reason
    );

    event MerkleRootAdded(
        bytes32 indexed root,
        uint256 indexed batchId,
        address indexed issuer,
        uint256 credentialCount
    );

    event TrustedIssuerUpdated(
        address indexed issuer,
        bool trusted,
        address indexed updater
    );
    event OfflineZkProofVerified(
        address indexed sender,
        uint256 indexed typeId,
        bytes32 nullifier
    );

    constructor(address admin) EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);

        // Set default expiry times for different credential types
        credentialTypeExpiry["DEGREE"] = 0; // Never expires
        credentialTypeExpiry["CERTIFICATE"] = 2 * 365 days; // 2 years
        credentialTypeExpiry["LICENSE"] = 365 days; // 1 year
        credentialTypeExpiry["IDENTITY"] = 5 * 365 days; // 5 years
    }

    function setZkProofManager(
        address manager
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        zkProofManager = IZkProofManager(manager);
    }

    /**
     * @dev Issues a signed credential for offline verification
     * @param holder Address of credential holder
     * @param credentialType Type of credential
     * @param credentialData Raw credential data
     * @return credential The signed offline credential
     */
    function issueOfflineCredential(
        address holder,
        string memory credentialType,
        bytes memory credentialData
    )
        external
        onlyRole(ISSUER_ROLE)
        returns (OfflineCredential memory credential)
    {
        require(holder != address(0), "Invalid holder");
        require(bytes(credentialType).length > 0, "Invalid credential type");
        require(credentialData.length > 0, "Empty credential data");
        require(trustedIssuers[msg.sender], "Issuer not trusted");

        bytes32 dataHash = keccak256(credentialData);
        uint256 nonce = uint256(
            keccak256(abi.encodePacked(holder, block.timestamp, block.number))
        );

        // Ensure nonce is unique for this holder
        require(!usedNonces[holder][nonce], "Nonce already used");
        usedNonces[holder][nonce] = true;

        uint256 expiresAt = block.timestamp +
            _getCredentialExpiry(credentialType);

        credential = OfflineCredential({
            holder: holder,
            credentialType: credentialType,
            dataHash: dataHash,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            nonce: nonce,
            issuer: msg.sender,
            signature: new bytes(0) // Will be filled by signing
        });

        // Create EIP-712 signature
        bytes32 structHash = keccak256(
            abi.encode(
                CREDENTIAL_TYPEHASH,
                credential.holder,
                keccak256(bytes(credential.credentialType)),
                credential.dataHash,
                credential.issuedAt,
                credential.expiresAt,
                credential.nonce,
                credential.issuer
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        credential.signature = _signHash(hash);

        emit CredentialIssued(
            holder,
            credentialType,
            dataHash,
            expiresAt,
            msg.sender
        );
    }

    /**
     * @dev Verifies an offline credential without blockchain access
     * @param credential The credential to verify
     * @return isValid Whether the credential is valid
     * @return reason Reason if invalid
     */
    function verifyOfflineCredential(
        OfflineCredential memory credential
    ) external view returns (bool isValid, string memory reason) {
        // Check if credential is revoked
        bytes32 credentialHash = _getCredentialHash(credential);
        if (revokedCredentials[credentialHash]) {
            return (false, "Credential revoked");
        }

        // Check expiry
        if (
            credential.expiresAt > 0 && block.timestamp > credential.expiresAt
        ) {
            return (false, "Credential expired");
        }

        // Check if issuer is trusted
        if (!trustedIssuers[credential.issuer]) {
            return (false, "Issuer not trusted");
        }

        // Verify signature
        bytes32 structHash = keccak256(
            abi.encode(
                CREDENTIAL_TYPEHASH,
                credential.holder,
                keccak256(bytes(credential.credentialType)),
                credential.dataHash,
                credential.issuedAt,
                credential.expiresAt,
                credential.nonce,
                credential.issuer
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);
        address recoveredSigner = hash.recover(credential.signature);

        if (recoveredSigner != credential.issuer) {
            return (false, "Invalid signature");
        }

        return (true, "Valid");
    }

    /**
     * @dev Creates a complete offline verification package
     * @param credential The base credential
     * @param merkleProof Optional merkle proof for batch verification
     * @return package Complete verification package
     */
    function createVerificationPackage(
        OfflineCredential memory credential,
        MerkleProof memory merkleProof
    ) external pure returns (OfflineVerificationPackage memory package) {
        package = OfflineVerificationPackage({
            credential: credential,
            merkleProof: merkleProof,
            additionalProofs: new bytes32[](0),
            packageVersion: 1
        });
    }

    /**
     * @dev Adds a Merkle root for batch credential verification
     * @param root Merkle root hash
     * @param batchId Batch identifier
     * @param credentialCount Number of credentials in batch
     */
    function addMerkleRoot(
        bytes32 root,
        uint256 batchId,
        uint256 credentialCount
    ) external onlyRole(ISSUER_ROLE) {
        require(root != bytes32(0), "Invalid root");
        require(credentialCount > 0, "Invalid credential count");
        require(merkleRoots[root] == 0, "Root already exists");

        merkleRoots[root] = block.timestamp;

        emit MerkleRootAdded(root, batchId, msg.sender, credentialCount);
    }

    /**
     * @dev Verifies a credential using Merkle proof
     * @param leaf Leaf hash (credential hash)
     * @param proof Merkle proof
     * @return isValid Whether the proof is valid
     */
    function verifyMerkleProof(
        bytes32 leaf,
        MerkleProof memory proof
    ) external view returns (bool isValid) {
        if (merkleRoots[proof.root] == 0) {
            return false; // Root not found
        }

        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.proof.length; i++) {
            bytes32 proofElement = proof.proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
        }

        return computedHash == proof.root;
    }

    /**
     * @dev Revokes a credential
     * @param credentialHash Hash of the credential to revoke
     * @param reason Reason for revocation
     */
    function revokeCredential(
        bytes32 credentialHash,
        string memory reason
    ) external onlyRole(ISSUER_ROLE) {
        revokedCredentials[credentialHash] = true;
        emit CredentialRevoked(credentialHash, msg.sender, reason);
    }

    /**
     * @dev Updates trusted issuer status
     * @param issuer Address of issuer
     * @param trusted Whether issuer is trusted
     */
    function updateTrustedIssuer(
        address issuer,
        bool trusted
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        trustedIssuers[issuer] = trusted;
        emit TrustedIssuerUpdated(issuer, trusted, msg.sender);
    }

    /**
     * @dev Generates QR code compatible data for offline verification
     * @param credential The credential to encode
     * @return qrData Base64 encoded data for QR code
     */
    function generateQRData(
        OfflineCredential memory credential
    ) external pure returns (bytes memory qrData) {
        // Encode credential data in a compact format
        qrData = abi.encode(
            credential.holder,
            credential.credentialType,
            credential.dataHash,
            credential.issuedAt,
            credential.expiresAt,
            credential.signature
        );
    }

    // Forward a ZK proof to the central manager for verification (reverts on failure)
    function verifyZkProof(
        uint256 typeId,
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external {
        require(address(zkProofManager) != address(0), "ZK manager not set");
        zkProofManager.verifyProof(
            typeId,
            _pA,
            _pB,
            _pC,
            publicSignals,
            nullifier
        );
        emit OfflineZkProofVerified(msg.sender, typeId, nullifier);
    }

    // Internal functions
    function _getCredentialHash(
        OfflineCredential memory credential
    ) internal pure returns (bytes32) {
        return
            keccak256(
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

    function _getCredentialExpiry(
        string memory credentialType
    ) internal view returns (uint256) {
        uint256 typeExpiry = credentialTypeExpiry[credentialType];
        return typeExpiry > 0 ? typeExpiry : defaultCredentialExpiry;
    }

    function _signHash(bytes32 hash) internal pure returns (bytes memory) {
        // In a real implementation, this would use a secure signing mechanism
        // For now, we return a placeholder that indicates signing is needed
        return abi.encodePacked("SIGN_REQUIRED:", hash);
    }

    // View functions for offline verification clients
    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function getCredentialTypeHash() external pure returns (bytes32) {
        return CREDENTIAL_TYPEHASH;
    }

    function isCredentialRevoked(
        bytes32 credentialHash
    ) external view returns (bool) {
        return revokedCredentials[credentialHash];
    }

    function isTrustedIssuer(address issuer) external view returns (bool) {
        return trustedIssuers[issuer];
    }
}
