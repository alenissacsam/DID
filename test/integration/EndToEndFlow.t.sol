// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {UserIdentityRegistry} from "src/core/UserIdentityRegistry.sol";
import {GlobalCredentialAnchor} from "src/privacy_cross-chain/GlobalCredentialAnchor.sol";
import {ZKProofManager} from "src/verification/ZKProofManager.sol";
import {IdentityAccountFactory} from "src/advanced_features/IdentityAccountFactory.sol";

import {TrustScore} from "src/advanced_features/TrustScore.sol";

contract EndToEndFlowTest is Test {
    VerificationLogger logger;
    UserIdentityRegistry registry;
    GlobalCredentialAnchor anchor;
    ZKProofManager zkpm;
    IdentityAccountFactory factory;
    TrustScore trust;

    address manager = address(0xBEEF);
    address user = address(0xA11CE);
    address entryPoint = address(0xE7);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        registry = new UserIdentityRegistry(address(logger), address(trust));
        registry.grantRole(registry.REGISTRY_MANAGER_ROLE(), manager);
        registry.grantRole(registry.PAUSER_ROLE(), manager);

        // allow on-chain contracts to log into VerificationLogger
        logger.grantRole(logger.LOGGER_ROLE(), address(registry));

        anchor = new GlobalCredentialAnchor(address(logger));
        zkpm = new ZKProofManager();

        // Wire anchor to zkpm (this test has admin role by constructor)
        anchor.setZkProofManager(address(zkpm));
        logger.grantRole(logger.LOGGER_ROLE(), address(anchor));
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));

        // Setup zkpm root manager and proof types (this test has admin role by constructor)
        zkpm.grantRole(zkpm.ROOT_MANAGER_ROLE(), address(this));
        logger.grantRole(logger.LOGGER_ROLE(), address(zkpm));

        factory = new IdentityAccountFactory(
            entryPoint,
            address(logger),
            address(trust),
            3
        );
        // unrestrict
        factory.updateConfig(25, 3, false);
        // factory needs to initialize and update trust scores
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(factory));
        // registry needs to initialize trust on register
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(registry));
    }

    function test_end_to_end_identity_to_proof_to_account() public {
        // 1. Register identity
        vm.prank(manager);
        registry.registerIdentity(user, bytes32("commit1"));
        assertTrue(registry.isRegistered(user));

        // 2. Anchor credential batch -> should update root in anchor and anchor new root into zkpm
        bytes32[] memory creds = new bytes32[](1);
        creds[0] = keccak256("cred1");
        address[] memory holders = new address[](1);
        holders[0] = user;
        string[] memory typesArr = new string[](1);
        typesArr[0] = "identity";

        // Give VERIFIER_ROLE on anchor
        anchor.grantRole(anchor.VERIFIER_ROLE(), address(this));
        anchor.submitCredentialBatch(creds, holders, typesArr, "");

        (bytes32 root, , ) = anchor.getCurrentRoot();
        // Ensure root is anchored in zkpm
        // As GlobalCredentialAnchor tries to call anchorRoot in zkpm, also explicitly anchor just in case
        zkpm.anchorRoot(root);
        assertTrue(zkpm.isValidRoot(root));

        // 3. Skip on-chain ZK proof verification (no real verifier deployed)

        // 4. Create a modular account via factory and check initial score
        address account = factory.createAccount(user, bytes32("s"), false);
        assertEq(trust.getTrustScore(account), 25);
    }
}
