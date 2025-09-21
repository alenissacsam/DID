// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";

/// Grants LOGGER_ROLE on VerificationLogger to TrustScore (or any target).
/// Usage:
///  forge script script/roles/GrantLoggerRole.s.sol:GrantLoggerRole \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
/// Env vars:
///  - LOGGER_ADDRESS: deployed VerificationLogger
///  - GRANTEE_ADDRESS: address to grant LOGGER_ROLE to (e.g., TrustScore)
contract GrantLoggerRole is Script {
    function run() external {
        address loggerAddr = vm.envAddress("LOGGER_ADDRESS");
        address grantee = vm.envAddress("GRANTEE_ADDRESS");
        require(
            loggerAddr != address(0) && grantee != address(0),
            "missing envs"
        );

        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);
        bytes32 role = keccak256("LOGGER_ROLE");
        VerificationLogger(loggerAddr).grantRole(role, grantee);
        vm.stopBroadcast();
        console.log("Granted LOGGER_ROLE to", grantee);
    }
}
