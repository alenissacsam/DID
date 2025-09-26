// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../../interfaces/IAccountModule.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

abstract contract BaseAccountModule is IAccountModule, AccessControl {
    bytes32 public constant ACCOUNT_ROLE = keccak256("ACCOUNT_ROLE");
    address public immutable account;

    constructor(address _account) {
        require(_account != address(0), "Invalid account");
        account = _account;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ACCOUNT_ROLE, _account);
    }

    modifier onlyAccount() {
        require(msg.sender == account, "Only account");
        _;
    }

    function onInstall(bytes calldata) external virtual onlyAccount {}

    function onUninstall(bytes calldata) external virtual onlyAccount {}
}
