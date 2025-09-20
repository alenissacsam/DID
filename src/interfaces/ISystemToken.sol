// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ISystemToken
 * @notice Interface for the SystemToken contract
 */
interface ISystemToken {
    function transfer(address to, uint256 amount) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);

    function balanceOf(address account) external view returns (uint256);

    function mint(address to, uint256 amount) external;

    function burn(address from, uint256 amount) external;
}
