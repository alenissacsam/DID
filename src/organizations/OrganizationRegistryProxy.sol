// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Minimal upgradeable-style proxy to reduce runtime size.
// It delegates calls to an implementation contract set at construction.

contract OrganizationRegistryProxy {
    // EIP-1967 implementation slot: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    bytes32 private constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    event Upgraded(address indexed implementation);

    constructor(address implementation_) {
        require(implementation_ != address(0), "impl");
        assembly {
            sstore(_IMPLEMENTATION_SLOT, implementation_)
        }
        emit Upgraded(implementation_);
    }

    function implementation() external view returns (address impl) {
        assembly {
            impl := sload(_IMPLEMENTATION_SLOT)
        }
    }

    fallback() external payable {
        assembly {
            let impl := sload(_IMPLEMENTATION_SLOT)
            if iszero(impl) {
                revert(0, 0)
            }
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}
