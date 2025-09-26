// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {OfflineVerificationManager} from "src/verification/OfflineVerificationManager.sol";
import {IZkProofManager} from "src/interfaces/IZkProofManager.sol";

contract DummyZkProofManager is IZkProofManager {
    bool public shouldVerify = true;
    mapping(bytes32 => bool) public usedNullifier;
    struct TypeInfo {
        string name;
        address verifier;
    }
    mapping(uint256 => TypeInfo) public types;
    uint256 public nextTypeId = 1;
    bytes32 public anchoredRoot = keccak256("root");

    function addType(string memory n) external returns (uint256 id) {
        id = nextTypeId++;
        types[id] = TypeInfo(n, address(0x1));
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }

    function anchorRoot(bytes32 root) external override {
        anchoredRoot = root;
    }

    function revokeRoot(bytes32 root) external override {
        if (anchoredRoot == root) anchoredRoot = bytes32(0);
    }

    function verifyProof(
        uint256 typeId,
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata signals,
        bytes32 nullifier
    ) external override {
        require(typeId != 0 && typeId < nextTypeId, "bad type");
        require(shouldVerify, "bad proof");
        require(!usedNullifier[nullifier], "nullifier used");
        require(
            signals.length > 0 && signals[0] == uint256(anchoredRoot),
            "bad root"
        );
        usedNullifier[nullifier] = true;
    }
}

contract OfflineVerificationManager_Extended is Test {
    OfflineVerificationManager off;
    DummyZkProofManager zk;
    address admin = address(this);
    uint256 issuerPk = 0xBEEF;
    address issuer = vm.addr(0xBEEF);
    address untrustedIssuer;
    address holder = address(0xCAFE);

    function setUp() public {
        off = new OfflineVerificationManager(admin);
        zk = new DummyZkProofManager();
        vm.startPrank(admin);
        off.updateTrustedIssuer(issuer, true);
        off.grantRole(off.ISSUER_ROLE(), issuer);
        // set up an untrusted issuer that still has the role to hit 'Issuer not trusted'
        untrustedIssuer = vm.addr(0xABCDEF);
        off.grantRole(off.ISSUER_ROLE(), untrustedIssuer);
        vm.stopPrank();
    }

    function _issue(
        string memory ctype,
        bytes memory raw
    )
        internal
        returns (OfflineVerificationManager.OfflineCredential memory cred)
    {
        vm.prank(issuer);
        cred = off.issueOfflineCredential(holder, ctype, raw);
        // Recreate struct hash & EIP712 typed data hash
        bytes32 typeHash = off.getCredentialTypeHash();
        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                cred.holder,
                keccak256(bytes(cred.credentialType)),
                cred.dataHash,
                cred.issuedAt,
                cred.expiresAt,
                cred.nonce,
                cred.issuer
            )
        );
        bytes32 domainSeparator = off.getDomainSeparator();
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(issuerPk, digest);
        cred.signature = abi.encodePacked(r, s, v);
    }

    function test_issue_and_verify_success() public {
        OfflineVerificationManager.OfflineCredential memory cred = _issue(
            "CERTIFICATE",
            bytes("abc")
        );
        (bool ok, string memory reason) = off.verifyOfflineCredential(cred);
        assertTrue(ok, reason);
    }

    function test_issue_reverts_untrusted_issuer() public {
        vm.prank(untrustedIssuer);
        vm.expectRevert(bytes("Issuer not trusted"));
        off.issueOfflineCredential(holder, "CERTIFICATE", bytes("x"));
    }

    function test_issue_invalid_inputs() public {
        vm.prank(issuer);
        vm.expectRevert(bytes("Invalid holder"));
        off.issueOfflineCredential(address(0), "CERTIFICATE", bytes("z"));
        vm.prank(issuer);
        vm.expectRevert(bytes("Invalid credential type"));
        off.issueOfflineCredential(holder, "", bytes("z"));
        vm.prank(issuer);
        vm.expectRevert(bytes("Empty credential data"));
        off.issueOfflineCredential(holder, "CERTIFICATE", bytes(""));
    }

    function test_revoke_and_verify_revoked() public {
        OfflineVerificationManager.OfflineCredential memory cred = _issue(
            "CERTIFICATE",
            bytes("abc")
        );
        bytes32 h = keccak256(
            abi.encode(
                cred.holder,
                cred.credentialType,
                cred.dataHash,
                cred.issuedAt,
                cred.nonce,
                cred.issuer
            )
        );
        vm.prank(issuer);
        off.revokeCredential(h, "fraud");
        (bool ok, string memory reason) = off.verifyOfflineCredential(cred);
        assertFalse(ok);
        assertEq(reason, "Credential revoked");
    }

    function test_verify_expired() public {
        // LICENSE has 365 day expiry configured in constructor
        OfflineVerificationManager.OfflineCredential memory cred = _issue(
            "LICENSE",
            bytes("abc")
        );
        // warp far beyond 1 year (LICENSE set to 365d) so it's expired
        vm.warp(block.timestamp + 366 days);
        (bool ok, string memory reason) = off.verifyOfflineCredential(cred);
        assertFalse(ok);
        assertEq(reason, "Credential expired");
    }

    function test_verify_invalid_signature_tamper() public {
        OfflineVerificationManager.OfflineCredential memory cred = _issue(
            "CERTIFICATE",
            bytes("abc")
        );
        // tamper dataHash (break signature)
        cred.dataHash = keccak256("other");
        (bool ok, string memory reason) = off.verifyOfflineCredential(cred);
        assertFalse(ok);
        assertEq(reason, "Invalid signature");
    }

    function test_add_merkle_root_and_verify_proof() public {
        bytes32 root = keccak256("r1");
        vm.prank(issuer);
        off.addMerkleRoot(root, 1, 5);
        // Construct a simple proof path of length 1 that matches directly
        OfflineVerificationManager.MerkleProof
            memory mp = OfflineVerificationManager.MerkleProof({
                proof: new bytes32[](0),
                root: root,
                leafIndex: 0,
                batchId: 1
            });
        bytes32 leaf = keccak256("some leaf");
        // With empty proof, only valid if leaf == root
        assertFalse(off.verifyMerkleProof(leaf, mp));
        assertTrue(off.verifyMerkleProof(root, mp));
    }

    function test_add_merkle_root_reverts_duplicates_and_invalid() public {
        bytes32 root = keccak256("r2");
        vm.startPrank(issuer);
        vm.expectRevert(bytes("Invalid root"));
        off.addMerkleRoot(bytes32(0), 1, 5);
        off.addMerkleRoot(root, 1, 5);
        vm.expectRevert(bytes("Root already exists"));
        off.addMerkleRoot(root, 2, 10);
        vm.expectRevert(bytes("Invalid credential count"));
        off.addMerkleRoot(keccak256("r3"), 3, 0);
        vm.stopPrank();
    }

    function test_generate_qr_data_format() public {
        OfflineVerificationManager.OfflineCredential memory cred = _issue(
            "CERTIFICATE",
            bytes("data")
        );
        bytes memory qr = off.generateQRData(cred);
        // decode first field holder + ensure includes dataHash
        (address h, , , , , ) = abi.decode(
            qr,
            (address, string, bytes32, uint256, uint256, bytes)
        );
        assertEq(h, cred.holder);
    }

    function test_update_trusted_issuer_access_control() public {
        vm.prank(issuer);
        vm.expectRevert();
        off.updateTrustedIssuer(address(0x1234), true);
        vm.prank(admin);
        off.updateTrustedIssuer(address(0x1234), true);
        assertTrue(off.isTrustedIssuer(address(0x1234)));
    }

    function test_verifyZkProof_manager_not_set_reverts() public {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[] memory signals = new uint256[](1);
        vm.expectRevert(bytes("ZK manager not set"));
        off.verifyZkProof(1, a, b, c, signals, keccak256("n"));
    }

    function test_verifyZkProof_forward_success_and_replay() public {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[] memory signals = new uint256[](1);
        signals[0] = uint256(zk.anchoredRoot());
        off.setZkProofManager(address(zk));
        zk.addType("AGE");
        off.verifyZkProof(1, a, b, c, signals, keccak256("n1"));
        vm.expectRevert();
        off.verifyZkProof(1, a, b, c, signals, keccak256("n1"));
    }
}
