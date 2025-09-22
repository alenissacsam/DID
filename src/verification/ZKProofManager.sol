// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IGroth16Verifier} from "../interfaces/IGroth16Verifier.sol";

/// @title ZKProofManager
/// @notice Manages ZK proof verification for identity attributes using Groth16
contract ZKProofManager is AccessControl, ReentrancyGuard {
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant ROOT_MANAGER_ROLE = keccak256("ROOT_MANAGER_ROLE");

    // Canonical type IDs for known circuits
    uint256 public constant TYPE_AGE_GTE = 0;
    uint256 public constant TYPE_ATTR_EQUALS = 1;
    uint256 public constant TYPE_INCOME_GTE = 2;
    uint256 public constant TYPE_AGE_LTE = 3;

    struct ProofType {
        string name;
        address verifierContract;
        bool isActive;
    }

    mapping(bytes32 => bool) public validRoots;
    mapping(bytes32 => uint256) public rootTimestamps;
    mapping(uint256 => ProofType) public proofTypes;
    mapping(bytes32 => bool) public usedNullifiers;
    uint256 public proofTypeCount;

    event RootAnchored(
        bytes32 indexed root,
        uint256 timestamp,
        address indexed anchor
    );
    event RootRevoked(bytes32 indexed root, uint256 timestamp);
    event ProofVerified(
        address indexed user,
        uint256 indexed proofType,
        bytes32 indexed root,
        bytes32 nullifier
    );
    event ProofTypeAdded(uint256 indexed typeId, string name, address verifier);
    event ProofTypeUpdated(
        uint256 indexed typeId,
        address newVerifier,
        bool isActive
    );

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(ROOT_MANAGER_ROLE, msg.sender);
    }

    /// @notice Add a new proof type with its verifier contract
    function addProofType(
        string calldata name,
        address verifierContract
    ) external onlyRole(ROOT_MANAGER_ROLE) {
        require(verifierContract != address(0), "Invalid verifier");

        proofTypes[proofTypeCount] = ProofType({
            name: name,
            verifierContract: verifierContract,
            isActive: true
        });

        emit ProofTypeAdded(proofTypeCount, name, verifierContract);
        proofTypeCount++;
    }

    /// @notice Update an existing proof type
    function updateProofType(
        uint256 typeId,
        address newVerifier,
        bool isActive
    ) external onlyRole(ROOT_MANAGER_ROLE) {
        require(typeId < proofTypeCount, "Invalid type ID");
        require(newVerifier != address(0), "Invalid verifier");

        proofTypes[typeId].verifierContract = newVerifier;
        proofTypes[typeId].isActive = isActive;

        emit ProofTypeUpdated(typeId, newVerifier, isActive);
    }

    /// @notice Anchor a Merkle root as valid for proof verification
    function anchorRoot(bytes32 root) external onlyRole(ROOT_MANAGER_ROLE) {
        require(!validRoots[root], "Root already anchored");
        require(root != bytes32(0), "Invalid root");

        validRoots[root] = true;
        rootTimestamps[root] = block.timestamp;

        emit RootAnchored(root, block.timestamp, msg.sender);
    }

    /// @notice Revoke a previously anchored root
    function revokeRoot(bytes32 root) external onlyRole(ROOT_MANAGER_ROLE) {
        require(validRoots[root], "Root not anchored");

        validRoots[root] = false;

        emit RootRevoked(root, block.timestamp);
    }

    /// @notice Generic verification entry point for any registered proof type
    /// @dev Assumes publicSignals[0] is the Merkle root (consistent with repo circuits)
    function verifyProof(
        uint256 typeId,
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external nonReentrant {
        require(typeId < proofTypeCount, "Invalid type ID");
        require(proofTypes[typeId].isActive, "Proof type disabled");
        require(!usedNullifiers[nullifier], "Nullifier already used");
        require(publicSignals.length >= 1, "Invalid public signals length");

        bytes32 root = bytes32(publicSignals[0]);
        require(validRoots[root], "Invalid root");

        IGroth16Verifier verifier = IGroth16Verifier(
            proofTypes[typeId].verifierContract
        );
        require(
            verifier.verifyProof(_pA, _pB, _pC, publicSignals),
            "Invalid proof"
        );

        usedNullifiers[nullifier] = true;
        emit ProofVerified(msg.sender, typeId, root, nullifier);
    }

    /// @notice Verify a ZK proof of type "age >= threshold"
    function verifyAgeProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external nonReentrant {
        require(proofTypes[0].isActive, "Age proof type disabled");
        require(!usedNullifiers[nullifier], "Nullifier already used");
        require(publicSignals.length >= 3, "Invalid public signals length");

        bytes32 root = bytes32(publicSignals[0]);
        require(validRoots[root], "Invalid root");

        // Call the age verifier contract
        IGroth16Verifier verifier = IGroth16Verifier(
            proofTypes[0].verifierContract
        );
        require(
            verifier.verifyProof(_pA, _pB, _pC, publicSignals),
            "Invalid proof"
        );

        usedNullifiers[nullifier] = true;

        emit ProofVerified(msg.sender, 0, root, nullifier);
    }

    /// @notice Verify a ZK proof of type "age <= threshold"
    function verifyAgeMaxProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external nonReentrant {
        require(proofTypes[3].isActive, "Age<= proof type disabled");
        require(!usedNullifiers[nullifier], "Nullifier already used");
        require(publicSignals.length >= 3, "Invalid public signals length");

        bytes32 root = bytes32(publicSignals[0]);
        require(validRoots[root], "Invalid root");

        // Call the age <= verifier contract
        IGroth16Verifier verifier = IGroth16Verifier(
            proofTypes[3].verifierContract
        );
        require(
            verifier.verifyProof(_pA, _pB, _pC, publicSignals),
            "Invalid proof"
        );

        usedNullifiers[nullifier] = true;

        emit ProofVerified(msg.sender, 3, root, nullifier);
    }

    /// @notice Verify a ZK proof of type "attribute equals"
    function verifyAttrProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external nonReentrant {
        require(proofTypes[1].isActive, "Attr proof type disabled");
        require(!usedNullifiers[nullifier], "Nullifier already used");
        require(publicSignals.length >= 2, "Invalid public signals length");

        bytes32 root = bytes32(publicSignals[0]);
        require(validRoots[root], "Invalid root");

        // Call the attribute verifier contract
        IGroth16Verifier verifier = IGroth16Verifier(
            proofTypes[1].verifierContract
        );
        require(
            verifier.verifyProof(_pA, _pB, _pC, publicSignals),
            "Invalid proof"
        );

        usedNullifiers[nullifier] = true;

        emit ProofVerified(msg.sender, 1, root, nullifier);
    }

    /// @notice Verify a ZK proof of type "income >= threshold"
    function verifyIncomeProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata publicSignals,
        bytes32 nullifier
    ) external nonReentrant {
        require(proofTypes[2].isActive, "Income proof type disabled");
        require(!usedNullifiers[nullifier], "Nullifier already used");
        require(publicSignals.length >= 2, "Invalid public signals length");

        bytes32 root = bytes32(publicSignals[0]);
        require(validRoots[root], "Invalid root");

        // Call the income verifier contract
        IGroth16Verifier verifier = IGroth16Verifier(
            proofTypes[2].verifierContract
        );
        require(
            verifier.verifyProof(_pA, _pB, _pC, publicSignals),
            "Invalid proof"
        );

        usedNullifiers[nullifier] = true;

        emit ProofVerified(msg.sender, 2, root, nullifier);
    }

    /// @notice Check if a root is valid and active
    function isValidRoot(bytes32 root) external view returns (bool) {
        return validRoots[root];
    }

    /// @notice Get proof type information
    function getProofType(
        uint256 typeId
    )
        external
        view
        returns (string memory name, address verifier, bool isActive)
    {
        require(typeId < proofTypeCount, "Invalid type ID");
        ProofType memory pt = proofTypes[typeId];
        return (pt.name, pt.verifierContract, pt.isActive);
    }

    /// @notice Return arrays of all proof types (names, verifiers, actives)
    function getAllProofTypes()
        external
        view
        returns (
            string[] memory names,
            address[] memory verifiers,
            bool[] memory actives
        )
    {
        names = new string[](proofTypeCount);
        verifiers = new address[](proofTypeCount);
        actives = new bool[](proofTypeCount);
        for (uint256 i = 0; i < proofTypeCount; i++) {
            ProofType memory pt = proofTypes[i];
            names[i] = pt.name;
            verifiers[i] = pt.verifierContract;
            actives[i] = pt.isActive;
        }
    }

    /// @notice Optional convenience: resolve a canonical type name to an ID if exists
    function resolveTypeId(
        string calldata name
    ) external view returns (bool found, uint256 typeId) {
        for (uint256 i = 0; i < proofTypeCount; i++) {
            if (
                keccak256(bytes(proofTypes[i].name)) == keccak256(bytes(name))
            ) {
                return (true, i);
            }
        }
        return (false, 0);
    }
}
