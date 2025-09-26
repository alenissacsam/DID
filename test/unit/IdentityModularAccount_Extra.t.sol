// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {IdentityModularAccount} from "../../src/advanced_features/dependencies/IdentityModularAccount.sol";
import {IVerificationLogger} from "../../src/interfaces/IVerificationLogger.sol";

contract DummyLogger is IVerificationLogger {
    function logEvent(string memory, address, bytes32) external override {}
}

contract PayableReceiver {
    event Received(uint256 v, bytes d);

    receive() external payable {
        emit Received(msg.value, "");
    }
}

contract IdentityModularAccount_Extra is Test {
    IdentityModularAccount acct;
    DummyLogger logger;
    PayableReceiver provider;
    address master = address(0xA11CE);
    address entryPoint = address(0xEE01);

    function setUp() public {
        logger = new DummyLogger();
        provider = new PayableReceiver();
        // Deploy with master owner
        acct = new IdentityModularAccount(entryPoint, master, address(logger));
        vm.deal(address(acct), 10 ether); // fund account
    }

    function _asOwner() internal {
        vm.prank(master);
    }

    function test_create_subscription_and_pay_success() public {
        _asOwner();
        bytes32 subId = acct.createSubscription(
            address(provider),
            1 ether,
            1 days,
            "svc",
            bytes("plan")
        );
        // fast-forward to due
        skip(1 days + 1);
        vm.prank(address(this)); // any caller can trigger according to current modifier (not owner restricted)
        bool ok = acct.executeSubscriptionPayment(subId);
        assertTrue(ok);
    }

    function test_subscription_payment_reverts_not_due() public {
        _asOwner();
        bytes32 subId = acct.createSubscription(
            address(provider),
            1 ether,
            1 days,
            "svc",
            bytes("plan")
        );
        vm.expectRevert(bytes("Payment not due yet"));
        acct.executeSubscriptionPayment(subId);
    }

    function test_subscription_payment_reverts_insufficient_balance() public {
        _asOwner();
        bytes32 subId = acct.createSubscription(
            address(provider),
            20 ether,
            1 days,
            "svc",
            bytes("plan")
        );
        skip(1 days + 1);
        vm.expectRevert(bytes("Insufficient balance"));
        acct.executeSubscriptionPayment(subId);
    }

    function test_cancel_subscription_blocks_payment() public {
        _asOwner();
        bytes32 subId = acct.createSubscription(
            address(provider),
            1 ether,
            1 days,
            "svc",
            bytes("plan")
        );
        _asOwner();
        acct.cancelSubscription(subId, "user cancel");
        skip(1 days + 1);
        vm.expectRevert(bytes("Subscription not active"));
        acct.executeSubscriptionPayment(subId);
    }

    function test_toggle_privacy_and_getters() public {
        _asOwner();
        // Session key creation path not reproduced; just toggle privacy on empty profile
        acct.togglePrivacyMode("app", true);
        (bytes32 hash, , uint256 interactions, bool privacy) = acct
            .getDAppProfile("app");
        assertEq(interactions, 0);
        assertTrue(privacy);
        assertEq(hash, bytes32(0));
    }
}
