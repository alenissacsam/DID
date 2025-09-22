// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./EduCertModularAccount.sol";
import {IEduCertAccountDeployer} from "../interfaces/IEduCertAccountDeployer.sol";

contract EduCertAccountDeployer is IEduCertAccountDeployer {
    function deploy(
        address entryPoint,
        address owner,
        address verificationLogger,
        bytes32 salt
    ) external returns (address account) {
        account = address(
            new EduCertModularAccount{salt: salt}(
                entryPoint,
                owner,
                verificationLogger
            )
        );
    }
}
