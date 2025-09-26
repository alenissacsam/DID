// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./dependencies/IdentityModularAccount.sol";
import {IIdentityAccountDeployer} from "../interfaces/IIdentityAccountDeployer.sol";

contract IdentityAccountDeployer is IIdentityAccountDeployer {
    function deploy(
        address entryPoint,
        address owner,
        address verificationLogger,
        bytes32 salt
    ) external returns (address account) {
        account = address(
            new IdentityModularAccount{salt: salt}(
                entryPoint,
                owner,
                verificationLogger
            )
        );
    }
}
