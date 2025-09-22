// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IEduCertAccountDeployer {
    function deploy(
        address entryPoint,
        address owner,
        address verificationLogger,
        bytes32 salt
    ) external returns (address account);
}
