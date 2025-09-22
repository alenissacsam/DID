// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ZKProofManager} from "src/verification/ZKProofManager.sol";
import {IGroth16Verifier} from "src/interfaces/IGroth16Verifier.sol";

contract TestGroth16Verifier is IGroth16Verifier {
    bool public shouldVerify;

    constructor(bool ok) {
        shouldVerify = ok;
    }

    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[] calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}

contract ZKProofManagerTest is Test {
    ZKProofManager manager;
    bytes32 root = bytes32(uint256(123));

    function setUp() public {
        manager = new ZKProofManager();

        vm.prank(address(this));
        manager.anchorRoot(root);
    }

    function test_anchor_and_revoke_root() public {
        assertTrue(manager.isValidRoot(root));
        manager.revokeRoot(root);
        assertFalse(manager.isValidRoot(root));
    }

    function test_verifyProof_generic_sets_nullifier() public {
        // Register type 0 (age_gte)
        TestGroth16Verifier v = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v));

        // Prepare dummy proof and signals; first signal is root
        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](3);
        pub[0] = uint256(root); // merkle root
        pub[1] = 18; // minAge
        pub[2] = 2025; // nowYear

        bytes32 nullifier = keccak256("n1");
        manager.verifyProof(0, pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }

    function test_verifyProof_rejects_replay_nullifier() public {
        TestGroth16Verifier v = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v));

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](3);
        pub[0] = uint256(root);
        pub[1] = 18;
        pub[2] = 2025;

        bytes32 nullifier = keccak256("n2");
        manager.verifyProof(0, pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));

        vm.expectRevert(bytes("Nullifier already used"));
        manager.verifyProof(0, pA, pB, pC, pub, nullifier);
    }

    function test_verifyAgeProof_specific_path() public {
        // Register proof types up to index 0 to satisfy verifyAgeProof
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](3);
        pub[0] = uint256(root);
        pub[1] = 18;
        pub[2] = 2025;
        bytes32 nullifier = keccak256("n3");
        manager.verifyAgeProof(pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }

    function test_verifyProof_invalid_root_reverts() public {
        TestGroth16Verifier v = new TestGroth16Verifier(true);
        manager.addProofType("attr_eq", address(v)); // id 0 if fresh, but safe regardless

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](2);
        pub[0] = uint256(bytes32(uint256(777))); // not anchored
        pub[1] = 0;
        bytes32 nullifier = keccak256("n4");

        vm.expectRevert(bytes("Invalid root"));
        manager.verifyProof(0, pA, pB, pC, pub, nullifier);
    }

    function test_anchorRoot_rejects_zero_and_duplicate() public {
        // zero root rejected
        vm.expectRevert(bytes("Invalid root"));
        manager.anchorRoot(bytes32(0));
        // duplicate root rejected (root was anchored in setUp)
        vm.expectRevert(bytes("Root already anchored"));
        manager.anchorRoot(root);
    }

    function test_revokeRoot_requires_anchored() public {
        bytes32 otherRoot = bytes32(uint256(999));
        vm.expectRevert(bytes("Root not anchored"));
        manager.revokeRoot(otherRoot);
    }

    function test_updateProofType_and_disable_generic() public {
        // Register type 0 and then disable it
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier vAlt = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.updateProofType(0, address(vAlt), false);

        // Check getProofType reflects new verifier and disabled flag
        (string memory name0, address ver0, bool active0) = manager
            .getProofType(0);
        assertEq(ver0, address(vAlt));
        assertFalse(active0);
        // Name is not asserted (string compare in solidity tests is clunky)
        name0;

        // Attempt generic verify should revert due to disabled type
        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](1);
        pub[0] = uint256(root);
        vm.expectRevert(bytes("Proof type disabled"));
        manager.verifyProof(0, pA, pB, pC, pub, keccak256("na"));
    }

    function test_specific_disabled_attr_reverts() public {
        // Ensure id 1 exists and is disabled
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.addProofType("attr_eq", address(v1)); // id 1
        manager.updateProofType(1, address(v1), false);

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](2);
        pub[0] = uint256(root);
        pub[1] = 0;
        vm.expectRevert(bytes("Attr proof type disabled"));
        manager.verifyAttrProof(pA, pB, pC, pub, keccak256("nb"));
    }

    function test_getAllProofTypes_returns_values() public {
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        TestGroth16Verifier v2 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // 0
        manager.addProofType("attr_eq", address(v1)); // 1
        manager.addProofType("income_gte", address(v2)); // 2

        (
            string[] memory names,
            address[] memory vers,
            bool[] memory actives
        ) = manager.getAllProofTypes();
        assertEq(names.length, 3);
        assertEq(vers.length, 3);
        assertEq(actives.length, 3);
        assertEq(vers[0], address(v0));
        assertEq(vers[1], address(v1));
        assertEq(vers[2], address(v2));
        assertTrue(actives[0] && actives[1] && actives[2]);
    }

    function test_verifyProof_invalid_type_id_reverts() public {
        // No types registered: any typeId is invalid
        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](1);
        pub[0] = uint256(root);
        vm.expectRevert(bytes("Invalid type ID"));
        manager.verifyProof(0, pA, pB, pC, pub, keccak256("nc"));
    }

    function test_verifyAttrProof_specific_path() public {
        // Register types so that id 1 exists
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.addProofType("attr_eq", address(v1)); // id 1

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](2);
        pub[0] = uint256(root); // root
        pub[1] = 0; // target
        bytes32 nullifier = keccak256("n5");
        manager.verifyAttrProof(pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }

    function test_verifyIncomeProof_specific_path() public {
        // Register types so that id 2 exists
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        TestGroth16Verifier v2 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.addProofType("attr_eq", address(v1)); // id 1
        manager.addProofType("income_gte", address(v2)); // id 2

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](2);
        pub[0] = uint256(root); // root
        pub[1] = 0; // minIncome
        bytes32 nullifier = keccak256("n6");
        manager.verifyIncomeProof(pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }

    function test_verifyAgeMaxProof_specific_path() public {
        // Register types so that id 3 exists
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        TestGroth16Verifier v2 = new TestGroth16Verifier(true);
        TestGroth16Verifier v3 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.addProofType("attr_eq", address(v1)); // id 1
        manager.addProofType("income_gte", address(v2)); // id 2
        manager.addProofType("age_lte", address(v3)); // id 3

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](3);
        pub[0] = uint256(root); // root
        pub[1] = 65; // maxAge
        pub[2] = 2025; // nowYear
        bytes32 nullifier = keccak256("n7");
        manager.verifyAgeMaxProof(pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }

    function test_generic_verify_attr_equals() public {
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.addProofType("attr_eq", address(v1)); // id 1

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](2);
        pub[0] = uint256(root);
        pub[1] = 0;
        bytes32 nullifier = keccak256("n8");
        manager.verifyProof(1, pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }

    function test_generic_verify_income_gte() public {
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        TestGroth16Verifier v2 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.addProofType("attr_eq", address(v1)); // id 1
        manager.addProofType("income_gte", address(v2)); // id 2

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](2);
        pub[0] = uint256(root);
        pub[1] = 0;
        bytes32 nullifier = keccak256("n9");
        manager.verifyProof(2, pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }

    function test_generic_verify_age_lte() public {
        TestGroth16Verifier v0 = new TestGroth16Verifier(true);
        TestGroth16Verifier v1 = new TestGroth16Verifier(true);
        TestGroth16Verifier v2 = new TestGroth16Verifier(true);
        TestGroth16Verifier v3 = new TestGroth16Verifier(true);
        manager.addProofType("age_gte", address(v0)); // id 0
        manager.addProofType("attr_eq", address(v1)); // id 1
        manager.addProofType("income_gte", address(v2)); // id 2
        manager.addProofType("age_lte", address(v3)); // id 3

        uint256[2] memory pA = [uint256(0), uint256(0)];
        uint256[2][2] memory pB = [
            [uint256(0), uint256(0)],
            [uint256(0), uint256(0)]
        ];
        uint256[2] memory pC = [uint256(0), uint256(0)];
        uint256[] memory pub = new uint256[](3);
        pub[0] = uint256(root);
        pub[1] = 65;
        pub[2] = 2025;
        bytes32 nullifier = keccak256("n10");
        manager.verifyProof(3, pA, pB, pC, pub, nullifier);
        assertTrue(manager.usedNullifiers(nullifier));
    }
}
