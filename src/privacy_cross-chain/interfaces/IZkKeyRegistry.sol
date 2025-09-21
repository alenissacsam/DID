// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IZkKeyRegistry {
    function setKey(
        string memory keyType,
        bytes memory verificationKey
    ) external;

    function getKey(
        string memory keyType
    )
        external
        view
        returns (
            bytes32 keyHash,
            bytes memory key,
            bool isActive,
            uint256 createdAt,
            address creator
        );
}
