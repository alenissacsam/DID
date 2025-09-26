// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IAccountModule {
    function moduleId() external pure returns (bytes32);

    function onInstall(bytes calldata data) external;

    function onUninstall(bytes calldata data) external;
}
