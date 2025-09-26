// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {TrustScore} from "../../src/advanced_features/TrustScore.sol";
import {UserIdentityRegistry} from "../../src/core/UserIdentityRegistry.sol";
import {FaceVerificationManager} from "../../src/verification/FaceVerificationManager.sol";
import {AadhaarVerificationManager} from "../../src/verification/AadhaarVerificationManager.sol";
import {IncomeVerificationManager} from "../../src/verification/IncomeVerificationManager.sol";
import {OfflineVerificationManager} from "../../src/verification/OfflineVerificationManager.sol";
import {MobileVerificationInterface} from "../../src/verification/MobileVerificationInterface.sol";
import {CertificateManager} from "../../src/organizations/CertificateManager.sol";
import {GuardianManager} from "../../src/advanced_features/GuardianManager.sol";
import {GlobalCredentialAnchor} from "../../src/privacy_cross-chain/GlobalCredentialAnchor.sol";
import {ZkKeyRegistry} from "../../src/privacy_cross-chain/ZkKeyRegistry.sol";
import {DisputeResolution} from "../../src/governance/DisputeResolution.sol";

library DeployLib {
    struct Core {
        VerificationLogger logger;
        TrustScore trust;
        UserIdentityRegistry registry;
    }

    function deployCore() internal returns (Core memory c) {
        c.logger = new VerificationLogger();
        c.trust = new TrustScore(address(c.logger));
        c.registry = new UserIdentityRegistry(
            address(c.logger),
            address(c.trust)
        );
    }

    struct VerificationStack {
        FaceVerificationManager face;
        AadhaarVerificationManager aadhaar;
        IncomeVerificationManager income;
    }

    function deployVerificationStack(
        address logger,
        address registry,
        address trust
    ) internal returns (VerificationStack memory v) {
        v.face = new FaceVerificationManager(logger, registry, trust);
        v.aadhaar = new AadhaarVerificationManager(
            logger,
            registry,
            trust,
            address(v.face)
        );
        v.income = new IncomeVerificationManager(
            logger,
            registry,
            trust,
            address(v.aadhaar)
        );
    }

    function deployOfflineMobile(
        address admin
    )
        internal
        returns (
            OfflineVerificationManager offline,
            MobileVerificationInterface mobile
        )
    {
        offline = new OfflineVerificationManager(admin);
        mobile = new MobileVerificationInterface(address(offline));
    }

    function deployOrganizations(
        address logger,
        address registry,
        address trust
    ) internal returns (CertificateManager cert) {
        cert = new CertificateManager(logger, registry, trust);
    }

    function deployGuardianAnchor(
        address logger,
        address registry,
        address trust
    )
        internal
        returns (
            GuardianManager guardian,
            GlobalCredentialAnchor anchor,
            ZkKeyRegistry zkReg
        )
    {
        guardian = new GuardianManager(logger, registry, trust);
        anchor = new GlobalCredentialAnchor(logger);
        zkReg = new ZkKeyRegistry(msg.sender);
        anchor.setZkKeyRegistry(address(zkReg));
    }

    function deployGovernance(
        address logger,
        address trust
    ) internal returns (DisputeResolution dispute) {
        dispute = new DisputeResolution(logger, trust);
    }
}
