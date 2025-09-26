// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ZkKeyRegistry} from "../../src/privacy_cross-chain/ZkKeyRegistry.sol";

contract CrossChain_ZkKeyRegistryTest is Test {
    ZkKeyRegistry reg;
    address admin = address(this);

    function setUp() public {
        reg = new ZkKeyRegistry(admin);
    }

    function test_set_and_get_key() public {
        bytes memory vk = abi.encode("verifier-bytes");
        reg.setKey("groth16", vk);
        (
            bytes32 h,
            bytes memory raw,
            bool active,
            uint256 created,
            address creator
        ) = reg.getKey("groth16");
        assertEq(h, keccak256(vk));
        assertEq(keccak256(raw), keccak256(vk));
        assertTrue(active);
        assertEq(creator, admin);
        assertGt(created, 0);
    }
}
