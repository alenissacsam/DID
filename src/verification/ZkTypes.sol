// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library ZkTypes {
    uint256 internal constant TYPE_AGE_GTE = 0;
    uint256 internal constant TYPE_ATTR_EQUALS = 1;
    uint256 internal constant TYPE_INCOME_GTE = 2;
    uint256 internal constant TYPE_AGE_LTE = 3;

    function ageGte() internal pure returns (uint256) {
        return TYPE_AGE_GTE;
    }

    function attrEquals() internal pure returns (uint256) {
        return TYPE_ATTR_EQUALS;
    }

    function incomeGte() internal pure returns (uint256) {
        return TYPE_INCOME_GTE;
    }

    function ageLte() internal pure returns (uint256) {
        return TYPE_AGE_LTE;
    }
}
