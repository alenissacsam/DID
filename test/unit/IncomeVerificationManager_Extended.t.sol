// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {IncomeVerificationManager} from "src/verification/IncomeVerificationManager.sol";
import {IVerificationLogger} from "src/interfaces/IVerificationLogger.sol";
import {IUserIdentityRegistry} from "src/interfaces/IUserIdentityRegistry.sol";
import {ITrustScore} from "src/interfaces/ITrustScore.sol";
import {IAadhaarVerificationManager} from "src/interfaces/IAadhaarVerificationManager.sol";

// Helper dummy contracts (must be top-level, not nested inside test contract)
contract DummyLogger is IVerificationLogger {
    event Logged(string eventType, address user, bytes32 dataHash);

    function logEvent(
        string memory eventType,
        address user,
        bytes32 dataHash
    ) external override {
        emit Logged(eventType, user, dataHash);
    }
}

contract DummyUserRegistry is IUserIdentityRegistry {
    mapping(address => bool) public registered;
    mapping(address => bool) public locked;
    struct Status {
        bool face;
        bool aadhaar;
        bool income;
        uint256 level;
    }
    mapping(address => Status) public statuses;

    function isVerified(address user) external view returns (bool) {
        return
            statuses[user].face &&
            statuses[user].aadhaar &&
            statuses[user].income;
    }

    function getUserCommitment(address) external pure returns (bytes32) {
        return bytes32(0);
    }

    function isRegistered(address user) external view returns (bool) {
        return registered[user];
    }

    function unlockIdentity(address user) external {
        locked[user] = false;
    }

    function getVerificationStatus(
        address user
    ) external view returns (bool, bool, bool, uint256) {
        Status memory s = statuses[user];
        return (s.face, s.aadhaar, s.income, s.level);
    }

    function updateVerificationStatus(
        address user,
        VerificationKind kind,
        bool status
    ) external {
        if (kind == VerificationKind.Face) statuses[user].face = status;
        else if (kind == VerificationKind.Aadhaar)
            statuses[user].aadhaar = status;
        else if (kind == VerificationKind.Income)
            statuses[user].income = status;
    }

    function isIdentityLocked(address user) external view returns (bool) {
        return locked[user];
    }

    function updateIdentityCommitment(address, bytes32) external {}

    function deregisterIdentity(address user) external {
        registered[user] = false;
    }

    // helpers
    function register(address user) external {
        registered[user] = true;
    }

    function setAadhaar(address user, bool v) external {
        statuses[user].aadhaar = v;
    }

    function setLocked(address user, bool v) external {
        locked[user] = v;
    }
}

contract DummyTrustScore is ITrustScore {
    mapping(address => int256) public scores;

    function getTrustScore(address user) external view returns (uint256) {
        return scores[user] < 0 ? 0 : uint256(scores[user]);
    }

    function updateScoreForGaslessTransaction(address) external {}

    function initializeUser(address user) external {
        if (scores[user] == 0) scores[user] = 0;
    }

    function updateScore(address user, int256 delta, string memory) external {
        scores[user] += delta;
    }

    function unlockScore(address) external {}
}

contract DummyAadhaar is IAadhaarVerificationManager {
    mapping(address => bool) public verified;

    function isAadhaarVerified(address user) external view returns (bool) {
        return verified[user];
    }

    function setVerified(address user, bool v) external {
        verified[user] = v;
    }
}

contract IncomeVerificationManager_ExtendedTest is Test {
    IncomeVerificationManager manager;
    DummyLogger logger;
    DummyUserRegistry registry;
    DummyTrustScore trust;
    DummyAadhaar aadhaar;

    address user = address(0x1234);
    address oracle = address(0xABCD);
    address verifier = address(0xBEEF);

    function setUp() public {
        logger = new DummyLogger();
        registry = new DummyUserRegistry();
        trust = new DummyTrustScore();
        aadhaar = new DummyAadhaar();

        manager = new IncomeVerificationManager(
            address(logger),
            address(registry),
            address(trust),
            address(aadhaar)
        );

        // test contract is deployer (has admin + roles); grant special roles to external addresses
        manager.grantRole(manager.INCOME_ORACLE_ROLE(), oracle);
        manager.grantRole(manager.VERIFIER_ROLE(), verifier);

        registry.register(user);
        aadhaar.setVerified(user, true);
    }

    function _request() internal {
        vm.prank(user);
        manager.requestIncomeVerification(
            keccak256("proof"),
            IncomeVerificationManager.IncomeRange.Lakh5to10,
            "ITR"
        );
    }

    function test_requestIncomeVerification_success() public {
        _request();
        (
            IncomeVerificationManager.IncomeRange range,
            uint256 ts,
            bool isVerified,
            string memory src,
            ,
            bool isExpired
        ) = manager.getIncomeVerificationInfo(user);
        assertEq(
            uint(range),
            uint(IncomeVerificationManager.IncomeRange.Lakh5to10)
        );
        assertEq(isVerified, false);
        assertEq(keccak256(bytes(src)), keccak256(bytes("ITR")));
        assertEq(isExpired, false);
    }

    function test_request_reverts_when_already_active() public {
        _request();
        vm.prank(user);
        vm.expectRevert(bytes("Income verification already active"));
        manager.requestIncomeVerification(
            keccak256("proof2"),
            IncomeVerificationManager.IncomeRange.Lakh1to5,
            "ITR"
        );
    }

    function test_completeIncomeVerification_success_and_trustscore_bonus()
        public
    {
        _request();
        vm.prank(oracle);
        manager.completeIncomeVerification(user, true, hex"01");
        // should now be verified
        (, , bool isVerified, , uint256 expiry, ) = manager
            .getIncomeVerificationInfo(user);
        assertTrue(isVerified);
        assertGt(expiry, block.timestamp);
        // trust score updated with base 25 + bonus 10 (range Lakh5to10)
        assertEq(trust.getTrustScore(user), 35);
    }

    function test_completeIncomeVerification_fail_path_penalty() public {
        _request();
        vm.prank(oracle);
        manager.completeIncomeVerification(user, false, hex"02");
        (, , bool isVerified, , uint256 expiry, ) = manager
            .getIncomeVerificationInfo(user);
        assertFalse(isVerified);
        assertEq(expiry, 0);
        assertEq(trust.getTrustScore(user), uint256(0)); // negative stored internally but view clamps
    }

    function test_complete_with_zk_proof_reverts_when_manager_not_set() public {
        _request();
        vm.prank(oracle);
        vm.expectRevert(bytes("ZK manager not set"));
        manager.completeIncomeVerificationWithProof(
            user,
            hex"03",
            [uint256(0), uint256(0)],
            [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
            [uint256(0), uint256(0)],
            new uint256[](0),
            bytes32(0)
        );
    }

    function test_renew_flow_and_history() public {
        test_completeIncomeVerification_success_and_trustscore_bonus();
        // simulate still valid (no warp beyond expiry)
        vm.prank(user);
        manager.renewIncomeVerification(
            keccak256("newProof"),
            IncomeVerificationManager.IncomeRange.Above25Lakh,
            "ITR"
        );
        // second request active & unverified
        (
            IncomeVerificationManager.IncomeRange range,
            ,
            bool isVerified,
            ,
            ,

        ) = manager.getIncomeVerificationInfo(user);
        assertEq(
            uint(range),
            uint(IncomeVerificationManager.IncomeRange.Above25Lakh)
        );
        assertFalse(isVerified);
        // history length 2 (original verified pushed in finalize + again on renewal pre-overwrite)
        IncomeVerificationManager.IncomeVerification[] memory hist = manager
            .getIncomeHistory(user);
        assertEq(hist.length, 2);
        assertTrue(hist[0].isVerified);
        assertTrue(hist[1].isVerified);
    }

    function test_renew_reverts_if_expired() public {
        test_completeIncomeVerification_success_and_trustscore_bonus();
        // warp beyond expiry
        vm.warp(block.timestamp + manager.INCOME_VERIFICATION_VALIDITY() + 1);
        vm.prank(user);
        vm.expectRevert(bytes("Current verification already expired"));
        manager.renewIncomeVerification(
            keccak256("p"),
            IncomeVerificationManager.IncomeRange.Lakh1to5,
            "ITR"
        );
    }

    function test_revoke_income_verification() public {
        test_completeIncomeVerification_success_and_trustscore_bonus();
        vm.prank(verifier);
        manager.revokeIncomeVerification(user, "fraud");
        (, , bool isVerified, , , ) = manager.getIncomeVerificationInfo(user);
        assertFalse(isVerified);
    }

    function test_bulk_complete_mixed() public {
        // user1 success user2 fail
        address user2 = address(0x5555);
        registry.register(user2);
        aadhaar.setVerified(user2, true);
        // create active requests
        vm.prank(user);
        manager.requestIncomeVerification(
            keccak256("p1"),
            IncomeVerificationManager.IncomeRange.Lakh1to5,
            "ITR"
        );
        vm.prank(user2);
        manager.requestIncomeVerification(
            keccak256("p2"),
            IncomeVerificationManager.IncomeRange.Below1Lakh,
            "ITR"
        );
        address[] memory users = new address[](2);
        users[0] = user;
        users[1] = user2;
        bool[] memory succ = new bool[](2);
        succ[0] = true;
        succ[1] = false;
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = hex"aa";
        sigs[1] = hex"bb";
        vm.prank(oracle);
        manager.bulkCompleteIncomeVerification(users, succ, sigs);
        (, , bool v1, , , ) = manager.getIncomeVerificationInfo(user);
        (, , bool v2, , , ) = manager.getIncomeVerificationInfo(user2);
        assertTrue(v1);
        assertFalse(v2);
    }

    function test_checkAndExpireVerifications() public {
        test_completeIncomeVerification_success_and_trustscore_bonus();
        vm.warp(block.timestamp + manager.INCOME_VERIFICATION_VALIDITY() + 2);
        address[] memory arr = new address[](1);
        arr[0] = user;
        manager.checkAndExpireVerifications(arr);
        (, , bool isVerified, , , ) = manager.getIncomeVerificationInfo(user);
        assertFalse(isVerified);
    }

    function test_isIncomeVerified_view_logic() public {
        _request();
        assertFalse(manager.isIncomeVerified(user));
        vm.prank(oracle);
        manager.completeIncomeVerification(user, true, hex"01");
        assertTrue(manager.isIncomeVerified(user));
        vm.warp(block.timestamp + manager.INCOME_VERIFICATION_VALIDITY() + 1);
        assertFalse(manager.isIncomeVerified(user));
    }
}
