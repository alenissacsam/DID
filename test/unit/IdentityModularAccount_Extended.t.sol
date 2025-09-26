// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {IdentityModularAccount} from "src/advanced_features/IdentityModularAccount.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IVerificationLogger} from "src/interfaces/IVerificationLogger.sol";
import {IEntryPoint} from "src/interfaces/IEntryPoint.sol";

contract DummyLoggerIMA is IVerificationLogger {
    function logEvent(string memory, address, bytes32) external override {}
}

// Minimal session module implementing required selectors used by account
contract DummySessionKeyModule {
    address public immutable account;
    struct Session {
        address key;
        string domain;
        uint256 validUntil;
        uint256 nonce;
    }
    mapping(address => Session) public sessions;

    constructor(address a) {
        account = a;
    }

    modifier onlyAccount() {
        require(msg.sender == account, "only acct");
        _;
    }

    function onInstall(bytes calldata) external onlyAccount {}

    function onUninstall(bytes calldata) external onlyAccount {}

    function createSessionKey(
        address key,
        string memory d,
        uint256 validFor,
        uint256 /*dailyLimit*/,
        bytes4[] memory
    ) external onlyAccount returns (address) {
        sessions[key] = Session(key, d, block.timestamp + validFor, 0);
        return key;
    }

    function useSessionKey(
        string memory d,
        address to,
        uint256 value,
        bytes memory data,
        bytes memory /*sig*/,
        uint256
    ) external onlyAccount returns (bytes memory) {
        // simple domain check
        // ignore signature validation for this dummy path; ensure domain matches existing session (first key we find)
        // iterate sessions (simplified: assume msg.sender already validated)
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "low level fail");
        return ret;
    }
}

// Minimal subscription module implementing create/execute/cancel semantics
contract DummySubscriptionModule2 {
    address public immutable account;

    constructor(address a) {
        account = a;
    }

    modifier onlyAccount() {
        require(msg.sender == account, "only acct");
        _;
    }
    struct Sub {
        address provider;
        uint256 amount;
        uint256 interval;
        uint256 last;
        bool active;
    }
    mapping(bytes32 => Sub) public subs;

    function onInstall(bytes calldata) external onlyAccount {}

    function onUninstall(bytes calldata) external onlyAccount {}

    function createSubscription(
        address provider,
        uint256 amount,
        uint256 interval,
        string memory service,
        bytes memory /*plan*/,
        uint256 nonce
    ) external onlyAccount returns (bytes32 id) {
        id = keccak256(
            abi.encodePacked(provider, amount, interval, service, nonce)
        );
        subs[id] = Sub(provider, amount, interval, block.timestamp, true);
    }

    function executePayment(bytes32 id) external onlyAccount returns (bool) {
        Sub storage s = subs[id];
        require(s.active, "Subscription not active");
        require(block.timestamp >= s.last + s.interval, "Payment not due yet");
        require(address(account).balance >= s.amount, "Insufficient balance");
        s.last = block.timestamp;
        (bool ok, ) = s.provider.call{value: s.amount}("");
        require(ok, "transfer fail");
        return true;
    }

    function cancel(bytes32 id, string memory) external onlyAccount {
        subs[id].active = false;
    }
}

contract IdentityModularAccount_Extended is Test {
    IdentityModularAccount acct;
    DummyLoggerIMA logger;
    address entryPoint = address(this); // test contract will simulate entryPoint
    uint256 ownerPk = 0xA11CE;
    address owner = vm.addr(ownerPk);
    DummySessionKeyModule session;
    DummySubscriptionModule2 sub;

    function setUp() public {
        logger = new DummyLoggerIMA();
        acct = new IdentityModularAccount(entryPoint, owner, address(logger));
        vm.deal(address(acct), 5 ether);
        // Deploy module instances (constructed by test contract)
        session = new DummySessionKeyModule(address(acct));
        sub = new DummySubscriptionModule2(address(acct));
        vm.startPrank(owner);
        acct.installModule(
            keccak256("SESSION_KEY_MODULE_V1"),
            address(session),
            ""
        );
        acct.installModule(
            keccak256("SUBSCRIPTION_MODULE_V1"),
            address(sub),
            ""
        );
        vm.stopPrank();
    }

    function _asOwner() internal {
        vm.prank(owner);
    }

    function test_install_uninstall_and_double_install_reverts() public {
        vm.startPrank(owner);
        vm.expectRevert(bytes("Installed"));
        acct.installModule(
            keccak256("SESSION_KEY_MODULE_V1"),
            address(session),
            ""
        );
        acct.uninstallModule(keccak256("SUBSCRIPTION_MODULE_V1"), "");
        vm.expectRevert(
            abi.encodeWithSelector(
                IdentityModularAccount.ErrorModuleMissing.selector,
                keccak256("SUBSCRIPTION_MODULE_V1")
            )
        );
        acct.createSubscription(
            address(0xBEEF),
            1,
            1 days,
            "svc",
            bytes("plan")
        );
        vm.stopPrank();
    }

    function test_execute_with_session_key_and_nonce_increments() public {
        vm.startPrank(owner);
        acct.createSessionKey(
            address(0x1001),
            "dapp",
            3600,
            0,
            new bytes4[](0)
        );
        vm.stopPrank();
        address receiver = address(new Receiver());
        // perform zero-value call to avoid module funding limitations
        vm.prank(owner);
        acct.executeWithSessionKey("dapp", receiver, 0, "", bytes("sig"));
        assertEq(acct.nonce(), 1);
    }

    function test_execute_with_session_key_reverts_locked_and_missing_module()
        public
    {
        vm.startPrank(owner);
        acct.uninstallModule(keccak256("SESSION_KEY_MODULE_V1"), "");
        vm.stopPrank();
        vm.expectRevert(
            abi.encodeWithSelector(
                IdentityModularAccount.ErrorModuleMissing.selector,
                keccak256("SESSION_KEY_MODULE_V1")
            )
        );
        acct.executeWithSessionKey("dapp", address(0x1), 0, "", "");
        vm.startPrank(owner);
        acct.installModule(
            keccak256("SESSION_KEY_MODULE_V1"),
            address(new DummySessionKeyModule(address(acct))),
            ""
        );
        acct.lockAccount();
        vm.stopPrank();
        vm.expectRevert(IdentityModularAccount.ErrorAccountLocked.selector);
        acct.executeWithSessionKey("dapp", address(0x1), 0, "", "");
    }

    function test_emergencyWithdraw_success_and_reverts() public {
        uint256 balBefore = owner.balance;
        // success path
        vm.prank(owner);
        acct.emergencyWithdraw();
        assertGt(owner.balance, balBefore);
        // lock then fund again and attempt withdraw (should revert)
        vm.deal(address(acct), 1 ether);
        vm.prank(owner);
        acct.lockAccount();
        vm.expectRevert(IdentityModularAccount.ErrorAccountLocked.selector);
        vm.prank(owner);
        acct.emergencyWithdraw();
    }

    function test_uninstall_missing_module_reverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IdentityModularAccount.ErrorModuleMissing.selector,
                keccak256("NOPE")
            )
        );
        vm.prank(owner);
        acct.uninstallModule(keccak256("NOPE"), "");
    }
}

contract Receiver {
    receive() external payable {}
}
