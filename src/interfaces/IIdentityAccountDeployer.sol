// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IIdentityAccountDeployer {
    function deploy(
        address entryPoint,
        address owner,
        address verificationLogger,
        bytes32 salt
    ) external returns (address account);
}
