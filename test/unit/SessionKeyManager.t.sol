// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import {VerificationLogger} from "../../src/core/VerificationLogger.sol";
import {SessionKeyManager} from "../../src/advanced_features/SessionKeyManager.sol";
import {ISessionKeyManager} from "../../src/interfaces/ISessionKeyManager.sol";

contract SessionKeyManagerTest is Test {
    VerificationLogger logger;
    SessionKeyManager skm;

    address manager = address(this);
    address wallet = address(0xCAFE);
    address key = address(0xBEEF);

    function setUp() public {
        logger = new VerificationLogger();
        skm = new SessionKeyManager(address(logger), manager);
        logger.grantRole(logger.LOGGER_ROLE(), address(skm));
    }

    function test_add_and_revoke_session_key() public {
        string[] memory funcs = new string[](1);
        funcs[0] = "transfer(address,uint256)";
        address[] memory addrs = new address[](1);
        addrs[0] = address(0x1);

        skm.addSessionKey(
            wallet,
            key,
            block.timestamp + 1 days,
            1 ether,
            funcs,
            addrs
        );
        assertTrue(skm.isSessionKeyValid(wallet, key));

        skm.revokeSessionKey(wallet, key);
        assertFalse(skm.isSessionKeyValid(wallet, key));
    }
}
