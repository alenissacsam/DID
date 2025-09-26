// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {FaceVerificationManager} from "src/verification/FaceVerificationManager.sol";
import {IVerificationLogger} from "src/interfaces/IVerificationLogger.sol";
import {IUserIdentityRegistry} from "src/interfaces/IUserIdentityRegistry.sol";
import {ITrustScore} from "src/interfaces/ITrustScore.sol";

// Dummy implementations reused for isolation
contract DummyLoggerF is IVerificationLogger {
    event Logged(string eventType, address user, bytes32 dataHash);

    function logEvent(
        string memory eventType,
        address user,
        bytes32 dataHash
    ) external override {
        emit Logged(eventType, user, dataHash);
    }
}

contract DummyUserRegistryF is IUserIdentityRegistry {
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

    function setLocked(address user, bool v) external {
        locked[user] = v;
    }
}

contract DummyTrustScoreF is ITrustScore {
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

contract FaceVerificationManager_ExtendedTest is Test {
    FaceVerificationManager manager;
    DummyLoggerF logger;
    DummyUserRegistryF registry;
    DummyTrustScoreF trust;

    address user = address(0x1111);
    address user2 = address(0x2222);
    address oracle = address(0xABCD);
    address verifier = address(0xBEEF);

    function setUp() public {
        logger = new DummyLoggerF();
        registry = new DummyUserRegistryF();
        trust = new DummyTrustScoreF();

        manager = new FaceVerificationManager(
            address(logger),
            address(registry),
            address(trust)
        );

        manager.grantRole(manager.ORACLE_ROLE(), oracle);
        manager.grantRole(manager.VERIFIER_ROLE(), verifier);

        registry.register(user);
        registry.register(user2);
    }

    function _request(address u, bytes32 hash, bytes32 live) internal {
        vm.prank(u);
        manager.requestFaceVerification(hash, live);
    }

    function _oracleComplete(
        address u,
        bool success,
        string memory provider,
        bytes memory sig
    ) internal {
        vm.prank(oracle);
        manager.completeFaceVerification(u, success, provider, sig);
    }

    function test_request_success_sets_active_and_retryCount() public {
        _request(user, keccak256("face1"), keccak256("live"));
        (bytes32 faceHash, , bool isVerified, , uint256 retryCount, ) = manager
            .getFaceVerificationInfo(user);
        assertEq(faceHash, keccak256("face1"));
        assertEq(isVerified, false);
        assertEq(retryCount, 1);
    }

    function test_request_reverts_when_already_active() public {
        _request(user, keccak256("face1"), keccak256("live"));
        vm.prank(user);
        vm.expectRevert(bytes("Face verification already active"));
        manager.requestFaceVerification(keccak256("face2"), keccak256("live2"));
    }

    function test_request_reverts_reused_face_hash() public {
        _request(user, keccak256("shared"), keccak256("live"));
        vm.prank(user2);
        vm.expectRevert(bytes("Face hash already used"));
        manager.requestFaceVerification(
            keccak256("shared"),
            keccak256("live2")
        );
    }

    function test_complete_success_path_trustscore_and_isFaceVerified_logic()
        public
    {
        _request(user, keccak256("face1"), keccak256("live"));
        bytes memory sig = new bytes(65);
        _oracleComplete(user, true, "ProviderA", sig);
        // Trust score increased by 25
        assertEq(trust.getTrustScore(user), 25);
        // After logic fix, isFaceVerified reflects successful completion
        assertTrue(manager.isFaceVerified(user));
    }

    function test_complete_failure_increments_failedAttempts_and_penalty()
        public
    {
        _request(user, keccak256("face1"), keccak256("live"));
        bytes memory sig = new bytes(65);
        _oracleComplete(user, false, "ProviderA", sig);
        (, , bool isVerified, , , uint256 failed) = manager
            .getFaceVerificationInfo(user);
        assertFalse(isVerified);
        assertEq(failed, 1);
        assertEq(trust.getTrustScore(user), 0); // penalty clamped
    }

    function test_multiple_failures_trigger_extended_cooldown() public {
        bytes memory sig = new bytes(65);
        // First attempt
        _request(user, keccak256("f1"), keccak256("l1"));
        _oracleComplete(user, false, "Prov", sig);
        // warp past cooldown to retry
        vm.warp(block.timestamp + manager.RETRY_COOLDOWN() + 1);
        _request(user, keccak256("f2"), keccak256("l2"));
        _oracleComplete(user, false, "Prov", sig);
        vm.warp(block.timestamp + manager.RETRY_COOLDOWN() + 1);
        _request(user, keccak256("f3"), keccak256("l3"));
        _oracleComplete(user, false, "Prov", sig); // failedAttempts now 3 triggers extended cooldown
        // immediate retry should fail due to cooldown
        vm.prank(user);
        vm.expectRevert(bytes("Retry cooldown not expired"));
        manager.requestFaceVerification(keccak256("f4"), keccak256("l4"));
    }

    function test_provider_length_and_signature_length_reverts() public {
        _request(user, keccak256("face1"), keccak256("live"));
        // short signature <65
        bytes memory badSig = new bytes(10);
        vm.prank(oracle);
        vm.expectRevert(bytes("Invalid signature length"));
        manager.completeFaceVerification(user, true, "P", badSig);
        // overly long provider string (51 chars)
        bytes memory sig = new bytes(65);
        string
            memory longProvider = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 52
        vm.prank(oracle);
        vm.expectRevert(bytes("Invalid provider length"));
        manager.completeFaceVerification(user, true, longProvider, sig);
    }

    function test_bulkComplete_mixed_outcomes() public {
        _request(user, keccak256("face1"), keccak256("live"));
        _request(user2, keccak256("face2"), keccak256("live2"));
        address[] memory users = new address[](2);
        users[0] = user;
        users[1] = user2;
        bool[] memory successes = new bool[](2);
        successes[0] = true;
        successes[1] = false;
        string[] memory providers = new string[](2);
        providers[0] = "P1";
        providers[1] = "P2";
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = new bytes(65);
        sigs[1] = new bytes(65);
        vm.prank(oracle);
        manager.bulkCompleteFaceVerification(users, successes, providers, sigs);
        assertEq(trust.getTrustScore(user), 25);
        (, , , , , uint256 failed2) = manager.getFaceVerificationInfo(user2);
        assertEq(failed2, 1);
    }

    function test_revoke_after_success() public {
        _request(user, keccak256("face1"), keccak256("live"));
        _oracleComplete(user, true, "P", new bytes(65));
        vm.prank(verifier);
        manager.revokeFaceVerification(user, "fraud");
    // isFaceVerified should now be false after revocation and trust score deducted
    assertEq(trust.getTrustScore(user), 0); // 25 added then 25 deducted
    assertFalse(manager.isFaceVerified(user));
    }

    function test_resetFailedAttempts() public {
        _request(user, keccak256("face1"), keccak256("live"));
        _oracleComplete(user, false, "P", new bytes(65));
        (, , , , , uint256 failed) = manager.getFaceVerificationInfo(user);
        assertEq(failed, 1);
        vm.prank(verifier);
        manager.resetFailedAttempts(user);
        (, , , , , uint256 failedAfter) = manager.getFaceVerificationInfo(user);
        assertEq(failedAfter, 0);
    }

    function test_canRetryVerification_logic() public {
        // initial true
        assertTrue(manager.canRetryVerification(user));
        bytes memory sig = new bytes(65);
        // do three requests to reach MAX_RETRY_ATTEMPTS
        _request(user, keccak256("f1"), keccak256("l1"));
        _oracleComplete(user, false, "P", sig); // retryCount 1
        vm.warp(block.timestamp + manager.RETRY_COOLDOWN() + 1);
        _request(user, keccak256("f2"), keccak256("l2"));
        _oracleComplete(user, false, "P", sig); // retryCount 2
        vm.warp(block.timestamp + manager.RETRY_COOLDOWN() + 1);
        _request(user, keccak256("f3"), keccak256("l3"));
        _oracleComplete(user, false, "P", sig); // retryCount 3
        assertFalse(manager.canRetryVerification(user));
    }
}
