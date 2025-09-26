// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "forge-std/Test.sol";
import {OfflineVerificationUtils} from "../../src/libs/OfflineVerificationUtils.sol";

contract OfflineVerificationUtils_Test is Test {
    function test_simple_hash_roundtrip() public {
        bytes memory payload = abi.encode("user", uint256(123));
        bytes32 h = keccak256(payload);
        // library currently thin; just assert keccak matches expectation path (placeholder for future helpers)
        assertEq(h, keccak256(abi.encode("user", uint256(123))));
    }
}
