// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {IdentityAccountFactory} from "src/advanced_features/IdentityAccountFactory.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";
import {TrustScore} from "src/advanced_features/TrustScore.sol";

contract IdentityAccountFactoryTest is Test {
    IdentityAccountFactory factory;
    VerificationLogger logger;
    TrustScore trust;

    address entryPoint = address(0xE7);
    address owner = address(0xBEEF);

    function setUp() public {
        logger = new VerificationLogger();
        trust = new TrustScore(address(logger));
        // allow contracts to log
        logger.grantRole(logger.LOGGER_ROLE(), address(trust));
        factory = new IdentityAccountFactory(
            entryPoint,
            address(logger),
            address(trust),
            3
        );
        // Unrestrict for direct creation in tests (this test has admin role)
        factory.updateConfig(25, 3, false);
        // allow factory to initialize and update trust scores
        trust.grantRole(trust.SCORE_MANAGER_ROLE(), address(factory));
    }

    function test_create_account_and_tracks_user() public {
        address account = factory.createAccount(owner, bytes32("salt"), false);
        address[] memory accounts = factory.getUserAccounts(owner);
        assertEq(accounts.length, 1);
        assertEq(accounts[0], account);
        // initial score set for the account address
        assertEq(trust.getTrustScore(account), 25);
    }
}
