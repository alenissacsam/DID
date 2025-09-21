// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import {IZkKeyRegistry} from "./interfaces/IZkKeyRegistry.sol";
import {IZkProofManager} from "../interfaces/IZkProofManager.sol";
import {MerkleLib} from "../libs/MerkleLib.sol";
import {ZkVerifyLib} from "../libs/ZkVerifyLib.sol";

contract GlobalCredentialAnchor is AccessControl, ReentrancyGuard {
    // Custom errors to reduce bytecode size
    error InvalidLogger();
    error InvalidRegistry();
    error InvalidManager();
    error EmptyBatch();
    error BatchTooLarge();
    error ArrayLengthMismatch();
    error InvalidHolder();
    error EmptyCredentialType();
    error RootNotActive();
    error VKeyNotActive();
    error CredentialNotFound();
    error AlreadyRevoked();
    error NullifierAlreadyUsed();
    error InvalidRange();
    error CredentialExists();
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

    mapping(uint256 => MerkleRoot) public merkleRoots;
    mapping(bytes32 => CredentialProof) public credentialProofs;
    mapping(bytes32 => bool) public nullifiers; // For double-spending prevention
    mapping(uint256 => BatchSubmission) public batchSubmissions;
    IZkKeyRegistry public zkKeyRegistry;
    IZkProofManager public zkProofManager;
    mapping(address => uint256[]) public userCredentials; // holder => credential indices
    mapping(bytes32 => uint256) public credentialToRootIndex;

    uint256 public currentRootIndex;
    uint256 public batchCounter;
    uint256 public totalCredentials;
    uint256 public revokedCredentials;

    IVerificationLogger public immutable verificationLogger;

    // Merkle tree storage - flattened tree structure
    mapping(uint256 => mapping(uint256 => bytes32)) public merkleTree; // level => index => hash

    event MerkleRootUpdated(
        uint256 indexed rootIndex,
        bytes32 indexed newRoot,
        uint256 credentialCount
    );
    event CredentialAnchored(
        bytes32 indexed credentialHash,
        address indexed holder,
        uint256 rootIndex
    );
    event CredentialRevoked(bytes32 indexed credentialHash, string reason);
    event BatchSubmitted(
        uint256 indexed batchId,
        uint256 credentialCount,
        bytes32 batchRoot
    );
    event ProofVerified(
        bytes32 indexed credentialHash,
        address indexed verifier,
        bool isValid
    );
    event NullifierUsed(bytes32 indexed nullifierHash, address indexed user);

    constructor(address _verificationLogger) {
        if (_verificationLogger == address(0)) revert InvalidLogger();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANCHOR_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);

        // Initialize genesis root
        _initializeGenesis();
    }

    function setZkKeyRegistry(
        address registry
    ) external onlyRole(ANCHOR_ADMIN_ROLE) {
        if (registry == address(0)) revert InvalidRegistry();
        zkKeyRegistry = IZkKeyRegistry(registry);
    }

    function setZkProofManager(
        address manager
    ) external onlyRole(ANCHOR_ADMIN_ROLE) {
        if (manager == address(0)) revert InvalidManager();
        zkProofManager = IZkProofManager(manager);
    }

    function submitCredentialBatch(
        bytes32[] memory credentialHashes,
        address[] memory holders,
        string[] memory credentialTypes,
        string memory metadataUri
    ) external onlyRole(VERIFIER_ROLE) nonReentrant returns (uint256) {
        if (credentialHashes.length == 0) revert EmptyBatch();
        if (credentialHashes.length > BATCH_SIZE) revert BatchTooLarge();
        if (
            !(credentialHashes.length == holders.length &&
                holders.length == credentialTypes.length)
        ) {
            revert ArrayLengthMismatch();
        }

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
            if (holders[i] == address(0)) revert InvalidHolder();
            if (bytes(credentialTypes[i]).length == 0)
                revert EmptyCredentialType();

            _anchorCredential(
                credentialHashes[i],
                holders[i],
                credentialTypes[i],
                batchId
            );
        }

        // Calculate batch root and update global Merkle tree
        bytes32 batchRoot = MerkleLib.calculateBatchRoot(credentialHashes);
        batchSubmissions[batchId].batchRoot = batchRoot;
        batchSubmissions[batchId].isProcessed = true;
        batchSubmissions[batchId].processedAt = block.timestamp;

        // Update global root
        _updateGlobalRoot(credentialHashes.length);

        verificationLogger.logEvent(
            "CBS",
            msg.sender,
            keccak256(
                abi.encodePacked(batchId, credentialHashes.length, batchRoot)
            )
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

        this.submitCredentialBatch(hashes, holders, types, metadataUri);
    }

    function verifyCredentialProof(
        bytes32 credentialHash,
        bytes32[] memory merkleProof,
        uint256 rootIndex,
        uint256 credentialIndex
    ) external view returns (bool) {
        if (!merkleRoots[rootIndex].isActive) revert RootNotActive();
        bytes32 computedRoot = MerkleLib.computeMerkleRoot(
            credentialHash,
            merkleProof,
            credentialIndex
        );
        return computedRoot == merkleRoots[rootIndex].root;
    }

    function verifyZkProof(
        string memory keyType,
        bytes memory proof,
        bytes memory publicInputs
    ) external onlyRole(VERIFIER_ROLE) returns (bool) {
        (bytes32 keyHash, bytes memory vkey, bool isActive, , ) = zkKeyRegistry
            .getKey(keyType);
        if (!isActive) revert VKeyNotActive();

        // Simplified ZK proof verification - in production use actual ZK libraries
        bool isValid = ZkVerifyLib.verify(vkey, proof, publicInputs);

        verificationLogger.logEvent(
            "ZPV",
            msg.sender,
            keccak256(abi.encodePacked(keyType, keyHash, isValid))
        );

        return isValid;
    }

    function revokeCredential(
        bytes32 credentialHash,
        string memory reason
    ) external onlyRole(ANCHOR_ADMIN_ROLE) {
        CredentialProof storage credential = credentialProofs[credentialHash];
        if (credential.credentialHash == bytes32(0))
            revert CredentialNotFound();
        if (credential.isRevoked) revert AlreadyRevoked();

        credential.isRevoked = true;
        revokedCredentials++;

        verificationLogger.logEvent(
            "CR",
            credential.holder,
            keccak256(abi.encodePacked(credentialHash, reason))
        );

        emit CredentialRevoked(credentialHash, reason);
    }

    // ZK key registration moved to ZkKeyRegistry to reduce contract size

    function useNullifier(bytes32 nullifierHash) external returns (bool) {
        if (nullifiers[nullifierHash]) revert NullifierAlreadyUsed();

        nullifiers[nullifierHash] = true;

        verificationLogger.logEvent("NU", msg.sender, nullifierHash);

        emit NullifierUsed(nullifierHash, msg.sender);
        return true;
    }

    function generateMerkleProof(
        bytes32 credentialHash
    ) external view returns (bytes32[] memory, uint256, uint256) {
        CredentialProof memory credential = credentialProofs[credentialHash];
        if (credential.credentialHash == bytes32(0))
            revert CredentialNotFound();

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

    function getCredentialProof(
        bytes32 credentialHash
    )
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

    function getUserCredentials(
        address user
    ) external view returns (uint256[] memory) {
        return userCredentials[user];
    }

    function getCurrentRoot()
        external
        view
        returns (bytes32, uint256, uint256)
    {
        MerkleRoot memory root = merkleRoots[currentRootIndex];
        return (root.root, root.timestamp, root.credentialCount);
    }

    function getRootHistory(
        uint256 fromIndex,
        uint256 toIndex
    ) external view returns (MerkleRoot[] memory) {
        if (!(fromIndex <= toIndex && toIndex <= currentRootIndex))
            revert InvalidRange();

        uint256 length = toIndex - fromIndex + 1;
        MerkleRoot[] memory roots = new MerkleRoot[](length);

        for (uint256 i = 0; i < length; i++) {
            roots[i] = merkleRoots[fromIndex + i];
        }

        return roots;
    }

    function getBatchSubmission(
        uint256 batchId
    )
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
        return (
            batch.credentialHashes,
            batch.submitter,
            batch.submittedAt,
            batch.isProcessed,
            batch.batchRoot
        );
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
        return (
            totalCredentials,
            revokedCredentials,
            currentRootIndex,
            batchCounter,
            currentRootIndex + 1
        );
    }

    function isNullifierUsed(
        bytes32 nullifierHash
    ) external view returns (bool) {
        return nullifiers[nullifierHash];
    }

    function isCredentialValid(
        bytes32 credentialHash
    ) external view returns (bool) {
        CredentialProof memory credential = credentialProofs[credentialHash];
        return
            credential.credentialHash != bytes32(0) &&
            !credential.isRevoked &&
            merkleRoots[credential.rootIndex].isActive;
    }

    function _anchorCredential(
        bytes32 credentialHash,
        address holder,
        string memory credentialType,
        uint256 /* batchId */
    ) private {
        if (credentialProofs[credentialHash].credentialHash != bytes32(0))
            revert CredentialExists();

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
            nullifierHash: keccak256(
                abi.encodePacked(credentialHash, holder, block.timestamp)
            )
        });

        userCredentials[holder].push(credentialIndex);
        credentialToRootIndex[credentialHash] = currentRootIndex;

        // Add to Merkle tree at leaf level
        merkleTree[0][credentialIndex] = credentialHash;

        emit CredentialAnchored(credentialHash, holder, currentRootIndex);
    }

    function _updateGlobalRoot(uint256 /* newCredentialCount */) private {
        currentRootIndex++;

        bytes32 newRoot = _calculateTreeRoot();
        bytes32 previousRoot = currentRootIndex > 0
            ? merkleRoots[currentRootIndex - 1].root
            : bytes32(0);

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

        // Deactivate old root and notify ZK manager
        if (currentRootIndex > 0) {
            bytes32 oldRoot = merkleRoots[currentRootIndex - 1].root;
            merkleRoots[currentRootIndex - 1].isActive = false;
            if (address(zkProofManager) != address(0)) {
                // Best-effort revoke (non-reverting if manager logic reverts is not trivial without try/catch)
                try zkProofManager.revokeRoot(oldRoot) {} catch {}
            }
        }

        verificationLogger.logEvent(
            "MRU",
            msg.sender,
            keccak256(
                abi.encodePacked(currentRootIndex, newRoot, totalCredentials)
            )
        );

        // Anchor the new root into the ZK manager if configured
        if (address(zkProofManager) != address(0)) {
            try zkProofManager.anchorRoot(newRoot) {} catch {}
        }

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
                bytes32 right = (i * 2 + 1 < levelSize)
                    ? merkleTree[level - 1][i * 2 + 1]
                    : bytes32(0);

                merkleTree[level][i] = MerkleLib.hashPair(left, right);
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

    // Pure helper functions moved to libraries (MerkleLib, ZkVerifyLib) to reduce bytecode size

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
