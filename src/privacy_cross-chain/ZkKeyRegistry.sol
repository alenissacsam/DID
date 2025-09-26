// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {IZkKeyRegistry} from "../interfaces/IZkKeyRegistry.sol";

contract ZkKeyRegistry is AccessControl, IZkKeyRegistry {
    bytes32 public constant KEY_ADMIN_ROLE = keccak256("KEY_ADMIN_ROLE");

    struct ZkVerificationKey {
        bytes32 keyHash;
        string keyType; // e.g., "groth16", "plonk"
        bytes verificationKey;
        bool isActive;
        uint256 createdAt;
        address creator;
    }

    mapping(string => ZkVerificationKey) public verificationKeys;

    event ZkKeyRegistered(string indexed keyType, bytes32 keyHash);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(KEY_ADMIN_ROLE, admin);
    }

    function setKey(
        string memory keyType,
        bytes memory verificationKey
    ) external override onlyRole(KEY_ADMIN_ROLE) {
        bytes32 keyHash = keccak256(verificationKey);
        verificationKeys[keyType] = ZkVerificationKey({
            keyHash: keyHash,
            keyType: keyType,
            verificationKey: verificationKey,
            isActive: true,
            createdAt: block.timestamp,
            creator: msg.sender
        });
        emit ZkKeyRegistered(keyType, keyHash);
    }

    function getKey(
        string memory keyType
    )
        external
        view
        override
        returns (
            bytes32 keyHash,
            bytes memory key,
            bool isActive,
            uint256 createdAt,
            address creator
        )
    {
        ZkVerificationKey memory zk = verificationKeys[keyType];
        return (
            zk.keyHash,
            zk.verificationKey,
            zk.isActive,
            zk.createdAt,
            zk.creator
        );
    }
}
