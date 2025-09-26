// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
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
        bool skipLookup = vm.envOr("SKIP_DEVOPS_LOOKUP", false);
        address loggerAddr = vm.envOr("LOGGER_ADDRESS", address(0));
        if (loggerAddr == address(0) && !skipLookup) {
            loggerAddr = DevOpsTools.get_most_recent_deployment(
                "VerificationLogger",
                block.chainid
            );
        }
        address grantee = vm.envOr("GRANTEE_ADDRESS", address(0));
        if (grantee == address(0) && !skipLookup) {
            // best-effort default to TrustScore
            grantee = DevOpsTools.get_most_recent_deployment(
                "TrustScore",
                block.chainid
            );
        }
        require(
            loggerAddr != address(0) && grantee != address(0),
            "missing logger/grantee"
        );

        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));
        if (pk != 0) {
            vm.startBroadcast(pk);
        } else {
            vm.startBroadcast();
        }
        bytes32 role = keccak256("LOGGER_ROLE");
        VerificationLogger(loggerAddr).grantRole(role, grantee);
        vm.stopBroadcast();
        console.log("Granted LOGGER_ROLE to", grantee);
    }
}
