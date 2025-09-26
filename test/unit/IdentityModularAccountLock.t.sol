// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {IdentityModularAccount} from "src/advanced_features/IdentityModularAccount.sol";
import {VerificationLogger} from "src/core/VerificationLogger.sol";

contract IdentityModularAccountLockTest is Test {
    IdentityModularAccount account;
    VerificationLogger logger;
    address entryPoint = address(0xE7);
    address owner = address(this);

    function setUp() public {
        logger = new VerificationLogger();
        logger.grantRole(logger.LOGGER_ROLE(), address(this));
        account = new IdentityModularAccount(
            entryPoint,
            owner,
            address(logger)
        );
    }

    function test_lock_blocks_session_and_subscription_creation() public {
        // install dummy modules so calls resolve
        DummySessionModule session = new DummySessionModule(address(account));
        DummySubscriptionModule sub = new DummySubscriptionModule(
            address(account)
        );
        account.installModule(
            keccak256("SESSION_KEY_MODULE_V1"),
            address(session),
            ""
        );
        account.installModule(
            keccak256("SUBSCRIPTION_MODULE_V1"),
            address(sub),
            ""
        );

        // lock
        account.lockAccount();
        vm.expectRevert(IdentityModularAccount.ErrorAccountLocked.selector);
        account.createSessionKey(
            address(0xAAA),
            "dapp",
            3600,
            0,
            new bytes4[](0)
        );

        vm.expectRevert(IdentityModularAccount.ErrorAccountLocked.selector);
        account.createSubscription(
            address(0xBEEF),
            1,
            1 days,
            "svc",
            abi.encode("p")
        );

        // unlock and succeed
        account.unlockAccount();
        account.createSessionKey(
            address(0xAAA),
            "dapp",
            3600,
            0,
            new bytes4[](0)
        );
        account.createSubscription(
            address(0xBEEF),
            1,
            1 days,
            "svc",
            abi.encode("p")
        );
    }
}

// Minimal dummy modules that satisfy interface expectations
import {BaseAccountModule} from "src/advanced_features/modules/BaseAccountModule.sol";

contract DummySessionModule is BaseAccountModule {
    constructor(address a) BaseAccountModule(a) {}

    function moduleId() external pure returns (bytes32) {
        return keccak256("SESSION_KEY_MODULE_V1");
    }

    function createSessionKey(
        address k,
        string memory,
        uint256,
        uint256,
        bytes4[] memory
    ) external onlyAccount returns (address) {
        return k;
    }
}

contract DummySubscriptionModule is BaseAccountModule {
    constructor(address a) BaseAccountModule(a) {}

    function moduleId() external pure returns (bytes32) {
        return keccak256("SUBSCRIPTION_MODULE_V1");
    }

    function createSubscription(
        address provider,
        uint256 amount,
        uint256 interval,
        string memory service,
        bytes memory,
        uint256 nonce
    ) external onlyAccount returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(provider, amount, interval, service, nonce)
            );
    }
}
