// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {SessionKeyModule} from "../../src/advanced_features/modules/SessionKeyModule.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract DummyTarget {
    event Ping();

    function ping() external payable {
        emit Ping();
    }
}

contract SessionKeyModuleTest is Test {
    using MessageHashUtils for bytes32;
    SessionKeyModule module;
    VerificationLogger logger;
    address account = address(this);

    // ephemeral EOA for session key
    uint256 sessionKeyPk;
    address sessionKeyAddr;

    DummyTarget target;

    function setUp() public {
        logger = new VerificationLogger();
        module = new SessionKeyModule(account, address(logger));
        logger.grantRole(logger.LOGGER_ROLE(), address(module));
        // generate private key deterministically for reproducibility
        sessionKeyPk = uint256(keccak256("session-key-test"));
        sessionKeyAddr = vm.addr(sessionKeyPk);
        target = new DummyTarget();
    }

    function test_create_and_use_session_key_positive() public {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("ping()"));
        address sk = module.createSessionKey(
            sessionKeyAddr,
            "dapp.example",
            1 days,
            5 ether,
            selectors
        );
        assertEq(sk, sessionKeyAddr);

        // Prepare a target call: call ping() on dummy target
        address to = address(target);
        uint256 value = 0;
        bytes memory callData = abi.encodeWithSignature("ping()");
        uint256 nonce = 0;
        // message encoded in module: keccak256(abi.encodePacked(to, value, data, nonce))
        bytes32 hash = keccak256(abi.encodePacked(to, value, callData, nonce));
        bytes32 ethSigned = hash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes memory ret = module.useSessionKey(
            "dapp.example",
            to,
            value,
            callData,
            sig,
            nonce
        );
        assertEq(ret.length, 0); // ping() returns nothing
    }

    function test_selector_not_allowed_reverts() public {
        // allow no selectors -> unrestricted? In current module design we added explicit selectors list requirement; assume non-empty means restriction.
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("ping()"));
        module.createSessionKey(
            sessionKeyAddr,
            "d1",
            1 days,
            1 ether,
            selectors
        );

        // Try calling with different selector (non-existent function) -> encode a random function signature
        address to = address(target);
        bytes memory callData = abi.encodeWithSignature("nonexistent()");
        uint256 nonce = 0;
        bytes32 hash = keccak256(
            abi.encodePacked(to, uint256(0), callData, nonce)
        );
        bytes32 ethSigned = hash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.expectRevert();
        module.useSessionKey("d1", to, 0, callData, sig, nonce);
    }

    function test_daily_limit_exceeded_reverts() public {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("ping()"));
        module.createSessionKey(sessionKeyAddr, "d2", 1 days, 1 wei, selectors); // daily limit 1 wei

        // Fund module to forward value
        vm.deal(address(module), 2 wei);

        // First call value=1 wei (should pass)
        address to = address(target);
        bytes memory callData = abi.encodeWithSignature("ping()");
        uint256 nonce = 0;
        bytes32 hash = keccak256(
            abi.encodePacked(to, uint256(1), callData, nonce)
        );
        bytes32 ethSigned = hash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);
        module.useSessionKey{value: 1 wei}("d2", to, 1, callData, sig, nonce);

        // Second call same day exceeding limit
        uint256 nonce2 = 1;
        bytes32 hash2 = keccak256(
            abi.encodePacked(to, uint256(1), callData, nonce2)
        );
        bytes32 ethSigned2 = hash2.toEthSignedMessageHash();
        (v, r, s) = vm.sign(sessionKeyPk, ethSigned2);
        bytes memory sig2 = abi.encodePacked(r, s, v);
        vm.expectRevert();
        module.useSessionKey{value: 1 wei}("d2", to, 1, callData, sig2, nonce2);
    }

    function test_expired_key_reverts() public {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("ping()"));
        module.createSessionKey(sessionKeyAddr, "d3", 1, 1 ether, selectors); // 1 second validity
        // Advance beyond validity
        vm.warp(block.timestamp + 2);
        address to = address(target);
        bytes memory callData = abi.encodeWithSignature("ping()");
        uint256 nonce = 0;
        bytes32 hash = keccak256(
            abi.encodePacked(to, uint256(0), callData, nonce)
        );
        bytes32 ethSigned = hash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyPk, ethSigned);
        bytes memory sig = abi.encodePacked(r, s, v);
        vm.expectRevert();
        module.useSessionKey("d3", to, 0, callData, sig, nonce);
    }
}
