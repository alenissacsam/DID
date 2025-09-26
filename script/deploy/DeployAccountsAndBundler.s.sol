// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DevOpsTools} from "@foundry-devops/src/DevOpsTools.sol";
import {IdentityAccountFactory} from "../../src/advanced_features/IdentityAccountFactory.sol";

/// Deploy IdentityAccountFactory and wire bundler + creator role.
/// Usage:
///   forge script script/deploy/DeployAccountsAndBundler.s.sol:DeployAccountsAndBundler \
///     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
contract DeployAccountsAndBundler is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);
        address bundler = vm.envOr("BUNDLER_ADDRESS", address(0));
        address entryPoint = vm.envAddress("ENTRYPOINT_ADDRESS");
        // Optional env overrides; else resolve last deployments
        address verificationLogger = vm.envOr(
            "VERIFICATION_LOGGER",
            address(0)
        );
        if (verificationLogger == address(0)) {
            verificationLogger = DevOpsTools.get_most_recent_deployment(
                "VerificationLogger",
                block.chainid
            );
        }
        address trustScore = vm.envOr("TRUST_SCORE", address(0));
        if (trustScore == address(0)) {
            trustScore = DevOpsTools.get_most_recent_deployment(
                "TrustScore",
                block.chainid
            );
        }
        uint256 maxAccountsPerUser = vm.envOr(
            "MAX_ACCOUNTS_PER_USER",
            uint256(1)
        );

        vm.startBroadcast(pk);

        // Deploy the factory
        IdentityAccountFactory factory = new IdentityAccountFactory(
            entryPoint,
            verificationLogger,
            trustScore,
            maxAccountsPerUser
        );

        // Set bundler and grant creator role (optional)
        factory.setBundler(bundler);
        bytes32 CREATOR_ROLE = keccak256("CREATOR_ROLE");
        factory.grantRole(CREATOR_ROLE, admin);

        console.log("IdentityAccountFactory:", address(factory));
        console.log("Bundler set:", bundler);
        console.log("Creator role granted to admin:", admin);

        vm.stopBroadcast();
    }
}
