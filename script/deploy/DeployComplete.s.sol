// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {DeployLib} from "./DeployLib.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";
import {ZkKeyRegistry} from "../../src/privacy_cross-chain/ZkKeyRegistry.sol";

/// One-shot script: deploy everything and wire roles.
/// Usage:
///  forge script script/deploy/DeployComplete.s.sol:DeployComplete \
///    --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast -vvvv
contract DeployComplete is Script {
    using DeployLib for *;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);
        vm.startBroadcast(pk);

        // 1) Deploy Core
        DeployLib.Core memory core = DeployLib.deployCore();
        console.log("VerificationLogger:", address(core.logger));
        console.log("TrustScore:", address(core.trust));
        console.log("UserIdentityRegistry:", address(core.registry));

        // 2) Deploy Verification Stack (Face/Aadhaar/Income)
        DeployLib.VerificationStack memory vf = DeployLib
            .deployVerificationStack(
                address(core.logger),
                address(core.registry),
                address(core.trust)
            );
        console.log("FaceVerificationManager:", address(vf.face));
        console.log("AadhaarVerificationManager:", address(vf.aadhaar));
        console.log("IncomeVerificationManager:", address(vf.income));

        // 3) Deploy Offline + Mobile
        DeployLib.deployOfflineMobile(admin);

        // 4) Deploy Organizations
        CertificateManager cert = DeployLib.deployOrganizations(
            address(core.logger),
            address(core.registry),
            address(core.trust)
        );
        console.log("CertificateManager:", address(cert));

        // 5) Deploy Guardian + Anchor
        (, , ZkKeyRegistry zkReg) = DeployLib.deployGuardianAnchor(
            address(core.logger),
            address(core.registry),
            address(core.trust)
        );
        console.log("ZkKeyRegistry:", address(zkReg));

        // 6) Deploy Governance (DisputeResolution)
        DeployLib.deployGovernance(address(core.logger), address(core.trust));

        // 7) Wire required roles
        bytes32 LOGGER_ROLE = keccak256("LOGGER_ROLE");
        bytes32 SCORE_MANAGER_ROLE = keccak256("SCORE_MANAGER_ROLE");

        // Logger permissions
        VerificationLogger(address(core.logger)).grantRole(
            LOGGER_ROLE,
            address(core.trust)
        );
        VerificationLogger(address(core.logger)).grantRole(
            LOGGER_ROLE,
            address(core.registry)
        );

        // TrustScore manager -> registry
        TrustScore(address(core.trust)).grantRole(
            SCORE_MANAGER_ROLE,
            address(core.registry)
        );

        // Give deployer default org roles for demos
        cert.grantRole(keccak256("ISSUER_ROLE"), admin);
        // Recognition system removed; badge roles obsolete.

        vm.stopBroadcast();

        console.log("Complete deployment + role wiring finished");
    }
}
