// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {AlchemyGasManager} from "../../src/advanced_features/AlchemyGasManager.sol";

/// Deploys AlchemyGasManager and sets initial config values.
/// Usage:
///   forge script script/deploy/DeployAlchemyGasManager.s.sol:DeployAlchemyGasManager \
///     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
contract DeployAlchemyGasManager is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address entryPoint = vm.envAddress("ENTRYPOINT_ADDRESS");
        address trustScore = vm.envAddress("TRUST_SCORE");
        address verificationLogger = vm.envAddress("VERIFICATION_LOGGER");

        string memory policyId = vm.envString("ALCHEMY_POLICY_ID");
        string memory appId = vm.envString("ALCHEMY_APP_ID");
        address paymaster = vm.envAddress("ALCHEMY_PAYMASTER");

        vm.startBroadcast(pk);
        AlchemyGasManager mgr = new AlchemyGasManager(
            entryPoint,
            trustScore,
            verificationLogger,
            policyId,
            appId,
            paymaster
        );

        console.log("AlchemyGasManager:", address(mgr));
        vm.stopBroadcast();
    }
}
