// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {SubscriptionModule} from "../../src/advanced_features/modules/SubscriptionModule.sol";

contract SubscriptionModuleTest is Test {
    SubscriptionModule module;
    address account = address(this);
    address provider = address(0xBEEF);
    MockLogger mlog;

    function setUp() public {
        module = new SubscriptionModule(account);
        mlog = new MockLogger();
        module.setLogger(address(mlog));
    }

    function test_create_and_pay_subscription() public {
        bytes memory details = abi.encode("basic");
        bytes32 id = module.createSubscription(
            provider,
            1 ether,
            1 days,
            "Service",
            details,
            0
        );
        SubscriptionModule.Subscription memory s = module.get(id);
        assertEq(s.amount, 1 ether);
        assertTrue(s.isActive);
        assertEq(s.failedAttempts, 0);
        assertEq(s.graceEndsAt, 0);

        // Fund module so it can pay provider
        vm.deal(address(module), 2 ether);
        vm.warp(block.timestamp + 1 days + 1);
        module.executePayment(id);
        s = module.get(id);
        assertEq(s.totalPaid, 1 ether);
        assertEq(s.paymentsCount, 1);
        assertEq(s.failedAttempts, 0);
        assertEq(s.graceEndsAt, 0);

        // Status helper should show Active (not due)
        (
            SubscriptionModule.Status status,
            ,
            uint256 nextPayment,
            bool due
        ) = module.getStatus(id);
        assertEq(uint256(status), uint256(SubscriptionModule.Status.Active));
        assertEq(due, false);
        assertGt(nextPayment, block.timestamp);

        // Logger should have at least SUB_CREATED + SUB_PAY_OK hashes stored
        assertTrue(mlog.count() >= 2, "logger events");
    }

    function test_payment_failure_starts_grace_and_auto_cancel() public {
        // provider is EOAs; we'll simulate failure by using a provider that reverts on receive.
        FailingReceiver failing = new FailingReceiver();
        bytes32 id = module.createSubscription(
            address(failing),
            0.5 ether,
            1 days,
            "FailingService",
            abi.encode("x"),
            1
        );
        // warp to due time
        vm.deal(address(module), 1 ether);
        vm.warp(block.timestamp + 1 days + 1);
        // expect revert ErrorPaymentFailed (selector) -> easier: try/catch pattern
        bool ok = module.executePayment(id);
        assertTrue(!ok, "expected failure return");
        SubscriptionModule.Subscription memory s = module.get(id);
        assertGt(s.graceEndsAt, 0, "grace started");
        assertEq(s.failedAttempts, 1);
        assertTrue(s.isActive, "still active during grace");

        // Status should report InGrace and due=false after failed attempt (nextPayment not advanced, but grace set)
        (SubscriptionModule.Status status, uint256 g, , bool due) = module
            .getStatus(id);
        assertEq(uint256(status), uint256(SubscriptionModule.Status.InGrace));
        assertEq(g, s.graceEndsAt);
        assertEq(due, true); // still due because nextPayment was reached

        // Advance beyond grace to trigger auto-cancel path
        vm.warp(s.graceEndsAt + 1);
        // Second attempt triggers auto cancel revert
        ok = module.executePayment(id);
        assertTrue(!ok, "expected auto-cancel failure");
        s = module.get(id);
        assertFalse(s.isActive, "auto-cancelled");

        // Status should now be AutoCanceled
        (status, , , ) = module.getStatus(id);
        assertEq(
            uint256(status),
            uint256(SubscriptionModule.Status.AutoCanceled)
        );
    }

    function test_failed_then_success_clears_grace() public {
        FailingFirstThenAccept receiver = new FailingFirstThenAccept();
        bytes32 id = module.createSubscription(
            address(receiver),
            0.25 ether,
            1 days,
            "FlakyService",
            abi.encode("p"),
            2
        );
        vm.deal(address(module), 1 ether);
        vm.warp(block.timestamp + 1 days + 1);
        // First attempt fails
        bool ok2 = module.executePayment(id);
        assertTrue(!ok2, "first failure should return false");
        SubscriptionModule.Subscription memory s = module.get(id);
        assertGt(
            s.graceEndsAt,
            block.timestamp,
            "grace timestamp set in future"
        );
        assertEq(s.failedAttempts, 1);

        // Second attempt (still within grace) should succeed now
        receiver.enable();
        vm.warp(block.timestamp + 60); // small move forward, still within grace
        ok2 = module.executePayment(id);
        assertTrue(ok2, "second attempt should succeed");
        s = module.get(id);
        assertEq(s.failedAttempts, 0);
        assertEq(s.graceEndsAt, 0);
        assertEq(s.paymentsCount, 1);

        // Status should be Active again
        (SubscriptionModule.Status status2, , , ) = module.getStatus(id);
        assertEq(uint256(status2), uint256(SubscriptionModule.Status.Active));
    }

    function test_manual_cancel_status() public {
        bytes32 id = module.createSubscription(
            provider,
            0.1 ether,
            1 days,
            "Svc",
            abi.encode("d"),
            77
        );
        vm.deal(address(module), 1 ether);
        vm.warp(block.timestamp + 1 days + 1);
        // pay once
        module.executePayment(id);
        module.cancel(id, "user");
        (SubscriptionModule.Status status, , , ) = module.getStatus(id);
        assertEq(uint256(status), uint256(SubscriptionModule.Status.Canceled));
    }
}

// Helper contracts
contract FailingReceiver {
    receive() external payable {
        revert("FAIL");
    }
}

contract FailingFirstThenAccept {
    bool public canReceive;

    function enable() external {
        canReceive = true;
    }

    receive() external payable {
        if (!canReceive) revert("FIRST_FAIL");
    }
}

contract MockLogger {
    struct Entry {
        string tag;
        address user;
        bytes32 hash;
    }
    Entry[] public entries;
    bytes32 public constant LOGGER_ROLE = keccak256("LOGGER_ROLE"); // mimic interface expectation

    function logEvent(
        string memory eventType,
        address user,
        bytes32 dataHash
    ) external {
        entries.push(Entry(eventType, user, dataHash));
    }

    function count() external view returns (uint256) {
        return entries.length;
    }
}
