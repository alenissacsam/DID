// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {ContractRegistry} from "../../src/core/ContractRegistry.sol";

contract Dummy {
    function hello() external pure returns (bytes32) {
        return keccak256("hi");
    }
}

contract ContractRegistryTest is Test {
    VerificationLogger logger;
    ContractRegistry registry;
    Dummy d1;
    Dummy d2;

    function setUp() public {
        logger = new VerificationLogger();
        registry = new ContractRegistry(address(logger));
        logger.grantRole(logger.LOGGER_ROLE(), address(registry));
        d1 = new Dummy();
        d2 = new Dummy();
    }

    function test_register_update_and_get() public {
        registry.registerContract("Dummy", address(d1), "v1");
        assertEq(registry.getContractAddress("Dummy"), address(d1));

        registry.updateContract("Dummy", address(d2), "v2");
        assertEq(registry.getContractAddress("Dummy"), address(d2));

        ContractRegistry.ContractInfo memory info = registry.getContractInfo(
            "Dummy"
        );
        assertEq(info.contractAddress, address(d2));
        assertEq(info.name, "Dummy");
        assertTrue(info.isActive);
        assertTrue(registry.verifyCodeIntegrity("Dummy"));
    }
}
