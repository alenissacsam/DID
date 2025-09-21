// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";

contract GlobalCredentialAnchor is AccessControl, ReentrancyGuard {
    bytes32 public constant ANCHOR_ADMIN_ROLE = keccak256("ANCHOR_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    uint256 public constant TREE_DEPTH = 32; // Supports up to 2^32 credentials
    uint256 public constant BATCH_SIZE = 100; // Maximum credentials per batch

    struct MerkleRoot {
        bytes32 root;
        uint256 timestamp;
        uint256 blockNumber;
        uint256 credentialCount;
        uint256 batchIndex;
        bool isActive;
        bytes32 previousRoot;
        string metadataUri;
    }

    struct CredentialProof {
        bytes32 credentialHash;
        address holder;
        uint256 rootIndex;
        bytes32[] merkleProof;
        uint256 credentialIndex;
        bool isRevoked;
        uint256 timestamp;
        string credentialType;
        bytes32 nullifierHash;
    }

    struct BatchSubmission {
        uint256 batchId;
        bytes32[] credentialHashes;
        address submitter;
        uint256 submittedAt;
        uint256 processedAt;
        bool isProcessed;
        bytes32 batchRoot;
        string metadataUri;
    }

    struct ZkVerificationKey {
        bytes32 keyHash;
        string keyType; // "groth16", "plonk", "stark"
        bytes verificationKey;
        bool isActive;
        uint256 createdAt;
        address creator;
    }

    mapping(uint256 => MerkleRoot) public merkleRoots;
    mapping(bytes32 => CredentialProof) public credentialProofs;
    mapping(bytes32 => bool) public nullifiers; // For double-spending prevention
    mapping(uint256 => BatchSubmission) public batchSubmissions;
    mapping(string => ZkVerificationKey) public verificationKeys;
    mapping(address => uint256[]) public userCredentials; // holder => credential indices
    mapping(bytes32 => uint256) public credentialToRootIndex;

    uint256 public currentRootIndex;
    uint256 public batchCounter;
    uint256 public totalCredentials;
    uint256 public revokedCredentials;

    IVerificationLogger public verificationLogger;

    // Merkle tree storage - flattened tree structure
    mapping(uint256 => mapping(uint256 => bytes32)) public merkleTree; // level => index => hash

    event MerkleRootUpdated(uint256 indexed rootIndex, bytes32 indexed newRoot, uint256 credentialCount);
    event CredentialAnchored(bytes32 indexed credentialHash, address indexed holder, uint256 rootIndex);
    event CredentialRevoked(bytes32 indexed credentialHash, string reason);
    event BatchSubmitted(uint256 indexed batchId, uint256 credentialCount, bytes32 batchRoot);
    event ProofVerified(bytes32 indexed credentialHash, address indexed verifier, bool isValid);
    event ZkKeyRegistered(string indexed keyType, bytes32 keyHash);
    event NullifierUsed(bytes32 indexed nullifierHash, address indexed user);

    constructor(address _verificationLogger) {
        require(_verificationLogger != address(0), "Invalid verification logger");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANCHOR_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);

        // Initialize genesis root
        _initializeGenesis();
    }

    function submitCredentialBatch(
        bytes32[] memory credentialHashes,
        address[] memory holders,
        string[] memory credentialTypes,
        string memory metadataUri
    ) public onlyRole(VERIFIER_ROLE) nonReentrant returns (uint256) {
        require(credentialHashes.length > 0, "Empty batch");
        require(credentialHashes.length <= BATCH_SIZE, "Batch too large");
        require(bytes(metadataUri).length > 0, "Invalid metadata URI");
        require(
            credentialHashes.length == holders.length && holders.length == credentialTypes.length,
            "Array length mismatch"
        );

        batchCounter++;
        uint256 batchId = batchCounter;

        // Create batch submission record
        batchSubmissions[batchId] = BatchSubmission({
            batchId: batchId,
            credentialHashes: credentialHashes,
            submitter: msg.sender,
            submittedAt: block.timestamp,
            processedAt: 0,
            isProcessed: false,
            batchRoot: bytes32(0),
            metadataUri: metadataUri
        });

        // Process each credential in the batch
        for (uint256 i = 0; i < credentialHashes.length; i++) {
            require(holders[i] != address(0), "Invalid holder address");
            require(bytes(credentialTypes[i]).length > 0, "Empty credential type");

            _anchorCredential(credentialHashes[i], holders[i], credentialTypes[i], batchId);
        }

        // Calculate batch root and update global Merkle tree
        bytes32 batchRoot = _calculateBatchRoot(credentialHashes);
        batchSubmissions[batchId].batchRoot = batchRoot;
        batchSubmissions[batchId].isProcessed = true;
        batchSubmissions[batchId].processedAt = block.timestamp;

        // Update global root
        _updateGlobalRoot(credentialHashes.length);

        verificationLogger.logEvent(
            "CREDENTIAL_BATCH_SUBMITTED",
            msg.sender,
            keccak256(abi.encodePacked(batchId, credentialHashes.length, batchRoot))
        );

        emit BatchSubmitted(batchId, credentialHashes.length, batchRoot);
        return batchId;
    }

    function anchorSingleCredential(
        bytes32 credentialHash,
        address holder,
        string memory credentialType,
        string memory metadataUri
    ) external onlyRole(VERIFIER_ROLE) {
        bytes32[] memory hashes = new bytes32[](1);
        address[] memory holders = new address[](1);
        string[] memory types = new string[](1);

        hashes[0] = credentialHash;
        holders[0] = holder;
        types[0] = credentialType;

        submitCredentialBatch(hashes, holders, types, metadataUri);
    }

    function verifyCredentialProof(
        bytes32 credentialHash,
        bytes32[] memory merkleProof,
        uint256 rootIndex,
        uint256 credentialIndex
    ) external view returns (bool) {
        require(merkleRoots[rootIndex].isActive, "Root not active");

        bytes32 computedRoot = _computeMerkleRoot(credentialHash, merkleProof, credentialIndex);
        return computedRoot == merkleRoots[rootIndex].root;
    }

    function verifyZkProof(string memory keyType, bytes memory proof, bytes memory publicInputs)
        external
        onlyRole(VERIFIER_ROLE)
        returns (bool)
    {
        ZkVerificationKey memory zkKey = verificationKeys[keyType];
        require(zkKey.isActive, "Verification key not active");

        // Simplified ZK proof verification - in production use actual ZK libraries
        bool isValid = _verifyProofInternal(zkKey.verificationKey, proof, publicInputs);

        verificationLogger.logEvent(
            "ZK_PROOF_VERIFIED", msg.sender, keccak256(abi.encodePacked(keyType, proof, isValid))
        );

        return isValid;
    }

    function revokeCredential(bytes32 credentialHash, string memory reason) external onlyRole(ANCHOR_ADMIN_ROLE) {
        CredentialProof storage credential = credentialProofs[credentialHash];
        require(credential.credentialHash != bytes32(0), "Credential not found");
        require(!credential.isRevoked, "Already revoked");

        credential.isRevoked = true;
        revokedCredentials++;

        verificationLogger.logEvent(
            "CREDENTIAL_REVOKED", credential.holder, keccak256(abi.encodePacked(credentialHash, reason))
        );

        emit CredentialRevoked(credentialHash, reason);
    }

    function registerZkVerificationKey(string memory keyType, bytes memory verificationKey)
        external
        onlyRole(ANCHOR_ADMIN_ROLE)
    {
        bytes32 keyHash = keccak256(verificationKey);

        verificationKeys[keyType] = ZkVerificationKey({
            keyHash: keyHash,
            keyType: keyType,
            verificationKey: verificationKey,
            isActive: true,
            createdAt: block.timestamp,
            creator: msg.sender
        });

        verificationLogger.logEvent("ZK_KEY_REGISTERED", msg.sender, keccak256(abi.encodePacked(keyType, keyHash)));

        emit ZkKeyRegistered(keyType, keyHash);
    }

    function useNullifier(bytes32 nullifierHash) external returns (bool) {
        require(!nullifiers[nullifierHash], "Nullifier already used");

        nullifiers[nullifierHash] = true;

        verificationLogger.logEvent("NULLIFIER_USED", msg.sender, nullifierHash);

        emit NullifierUsed(nullifierHash, msg.sender);
        return true;
    }

    function generateMerkleProof(bytes32 credentialHash) external view returns (bytes32[] memory, uint256, uint256) {
        CredentialProof memory credential = credentialProofs[credentialHash];
        require(credential.credentialHash != bytes32(0), "Credential not found");

        bytes32[] memory proof = new bytes32[](TREE_DEPTH);
        uint256 index = credential.credentialIndex;
        uint256 proofLength = 0;

        // Generate Merkle proof by traversing up the tree
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            uint256 siblingIndex = index ^ 1; // XOR with 1 to get sibling

            if (merkleTree[level][siblingIndex] != bytes32(0)) {
                proof[proofLength] = merkleTree[level][siblingIndex];
                proofLength++;
            }

            index = index / 2;
            if (index == 0) break;
        }

        // Resize proof array to actual length
        bytes32[] memory finalProof = new bytes32[](proofLength);
        for (uint256 i = 0; i < proofLength; i++) {
            finalProof[i] = proof[i];
        }

        return (finalProof, credential.rootIndex, credential.credentialIndex);
    }

    function getCredentialProof(bytes32 credentialHash)
        external
        view
        returns (
            address holder,
            uint256 rootIndex,
            uint256 credentialIndex,
            bool isRevoked,
            string memory credentialType
        )
    {
        CredentialProof memory credential = credentialProofs[credentialHash];
        return (
            credential.holder,
            credential.rootIndex,
            credential.credentialIndex,
            credential.isRevoked,
            credential.credentialType
        );
    }

    function getUserCredentials(address user) external view returns (uint256[] memory) {
        return userCredentials[user];
    }

    function getCurrentRoot() external view returns (bytes32, uint256, uint256) {
        MerkleRoot memory root = merkleRoots[currentRootIndex];
        return (root.root, root.timestamp, root.credentialCount);
    }

    function getRootHistory(uint256 fromIndex, uint256 toIndex) external view returns (MerkleRoot[] memory) {
        require(fromIndex <= toIndex && toIndex <= currentRootIndex, "Invalid range");

        uint256 length = toIndex - fromIndex + 1;
        MerkleRoot[] memory roots = new MerkleRoot[](length);

        for (uint256 i = 0; i < length; i++) {
            roots[i] = merkleRoots[fromIndex + i];
        }

        return roots;
    }

    function getBatchSubmission(uint256 batchId)
        external
        view
        returns (
            bytes32[] memory credentialHashes,
            address submitter,
            uint256 submittedAt,
            bool isProcessed,
            bytes32 batchRoot
        )
    {
        BatchSubmission memory batch = batchSubmissions[batchId];
        return (batch.credentialHashes, batch.submitter, batch.submittedAt, batch.isProcessed, batch.batchRoot);
    }

    function getGlobalStats()
        external
        view
        returns (
            uint256 totalCredentialsCount,
            uint256 revokedCredentialsCount,
            uint256 currentRootIndexValue,
            uint256 totalBatches,
            uint256 activeRoots
        )
    {
        return (totalCredentials, revokedCredentials, currentRootIndex, batchCounter, currentRootIndex + 1);
    }

    function isNullifierUsed(bytes32 nullifierHash) external view returns (bool) {
        return nullifiers[nullifierHash];
    }

    function isCredentialValid(bytes32 credentialHash) external view returns (bool) {
        CredentialProof memory credential = credentialProofs[credentialHash];
        return credential.credentialHash != bytes32(0) && !credential.isRevoked
            && merkleRoots[credential.rootIndex].isActive;
    }

    function _anchorCredential(
        bytes32 credentialHash,
        address holder,
        string memory credentialType,
        uint256 /* batchId */
    ) private {
        require(credentialProofs[credentialHash].credentialHash == bytes32(0), "Credential already anchored");

        uint256 credentialIndex = totalCredentials;
        totalCredentials++;

        credentialProofs[credentialHash] = CredentialProof({
            credentialHash: credentialHash,
            holder: holder,
            rootIndex: currentRootIndex,
            merkleProof: new bytes32[](0), // Will be generated on demand
            credentialIndex: credentialIndex,
            isRevoked: false,
            timestamp: block.timestamp,
            credentialType: credentialType,
            nullifierHash: keccak256(abi.encodePacked(credentialHash, holder, block.timestamp))
        });

        userCredentials[holder].push(credentialIndex);
        credentialToRootIndex[credentialHash] = currentRootIndex;

        // Add to Merkle tree at leaf level
        merkleTree[0][credentialIndex] = credentialHash;

        emit CredentialAnchored(credentialHash, holder, currentRootIndex);
    }

    function _updateGlobalRoot(uint256 /* newCredentialCount */ ) private {
        currentRootIndex++;

        bytes32 newRoot = _calculateTreeRoot();
        bytes32 previousRoot = currentRootIndex > 0 ? merkleRoots[currentRootIndex - 1].root : bytes32(0);

        merkleRoots[currentRootIndex] = MerkleRoot({
            root: newRoot,
            timestamp: block.timestamp,
            blockNumber: block.number,
            credentialCount: totalCredentials,
            batchIndex: batchCounter,
            isActive: true,
            previousRoot: previousRoot,
            metadataUri: ""
        });

        // Deactivate old root
        if (currentRootIndex > 0) {
            merkleRoots[currentRootIndex - 1].isActive = false;
        }

        verificationLogger.logEvent(
            "MERKLE_ROOT_UPDATED", msg.sender, keccak256(abi.encodePacked(currentRootIndex, newRoot, totalCredentials))
        );

        emit MerkleRootUpdated(currentRootIndex, newRoot, totalCredentials);
    }

    function _calculateTreeRoot() private returns (bytes32) {
        if (totalCredentials == 0) return bytes32(0);

        // Build tree bottom-up
        uint256 levelSize = totalCredentials;

        for (uint256 level = 1; level < TREE_DEPTH && levelSize > 1; level++) {
            uint256 nextLevelSize = (levelSize + 1) / 2;

            for (uint256 i = 0; i < nextLevelSize; i++) {
                bytes32 left = merkleTree[level - 1][i * 2];
                bytes32 right = (i * 2 + 1 < levelSize) ? merkleTree[level - 1][i * 2 + 1] : bytes32(0);

                merkleTree[level][i] = _hashPair(left, right);
            }

            levelSize = nextLevelSize;
        }

        // Root is at the top level with index 0
        for (uint256 level = 1; level < TREE_DEPTH; level++) {
            if (merkleTree[level][0] != bytes32(0)) {
                return merkleTree[level][0];
            }
        }

        return merkleTree[0][0]; // Single leaf case
    }

    function _calculateBatchRoot(bytes32[] memory credentialHashes) private pure returns (bytes32) {
        if (credentialHashes.length == 0) return bytes32(0);
        if (credentialHashes.length == 1) return credentialHashes[0];

        bytes32[] memory currentLevel = credentialHashes;

        while (currentLevel.length > 1) {
            uint256 nextLevelLength = (currentLevel.length + 1) / 2;
            bytes32[] memory nextLevel = new bytes32[](nextLevelLength);

            for (uint256 i = 0; i < nextLevelLength; i++) {
                bytes32 left = currentLevel[i * 2];
                bytes32 right = (i * 2 + 1 < currentLevel.length) ? currentLevel[i * 2 + 1] : bytes32(0);
                nextLevel[i] = _hashPair(left, right);
            }

            currentLevel = nextLevel;
        }

        return currentLevel[0];
    }

    function _computeMerkleRoot(bytes32 leaf, bytes32[] memory proof, uint256 index) private pure returns (bytes32) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (index % 2 == 0) {
                computedHash = _hashPair(computedHash, proofElement);
            } else {
                computedHash = _hashPair(proofElement, computedHash);
            }

            index = index / 2;
        }

        return computedHash;
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _verifyProofInternal(bytes memory verificationKey, bytes memory proof, bytes memory publicInputs)
        private
        pure
        returns (bool)
    {
        // Simplified verification - in production use actual ZK libraries like:
        // - Circomlib for Groth16
        // - PLONK verification libraries
        // - StarkWare STARK verifiers

        // For now, just check that all parameters are non-empty
        return verificationKey.length > 0 && proof.length > 0 && publicInputs.length > 0;
    }

    function _initializeGenesis() private {
        merkleRoots[0] = MerkleRoot({
            root: bytes32(0),
            timestamp: block.timestamp,
            blockNumber: block.number,
            credentialCount: 0,
            batchIndex: 0,
            isActive: true,
            previousRoot: bytes32(0),
            metadataUri: "genesis"
        });
    }
}
