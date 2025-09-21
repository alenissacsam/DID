// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {EduCertAccountFactory} from "../../src/advanced_features/EduCertAccountFactory.sol";

/// Deploy EduCertAccountFactory and wire bundler + creator role.
/// Usage:
///   forge script script/deploy/DeployAccountsAndBundler.s.sol:DeployAccountsAndBundler \
///     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
contract DeployAccountsAndBundler is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);
        address bundler = vm.envAddress("BUNDLER_ADDRESS");
        address entryPoint = vm.envAddress("ENTRYPOINT_ADDRESS");
        address verificationLogger = vm.envAddress("VERIFICATION_LOGGER");
        address trustScore = vm.envAddress("TRUST_SCORE");
        uint256 maxAccountsPerUser = vm.envOr(
            "MAX_ACCOUNTS_PER_USER",
            uint256(1)
        );

        vm.startBroadcast(pk);

        // Deploy the factory
        EduCertAccountFactory factory = new EduCertAccountFactory(
            entryPoint,
            verificationLogger,
            trustScore,
            maxAccountsPerUser
        );

        // Set bundler and grant creator role (optional)
        factory.setBundler(bundler);
        bytes32 CREATOR_ROLE = keccak256("CREATOR_ROLE");
        factory.grantRole(CREATOR_ROLE, admin);

        console.log("EduCertAccountFactory:", address(factory));
        console.log("Bundler set:", bundler);
        console.log("Creator role granted to admin:", admin);

        vm.stopBroadcast();
    }
}
