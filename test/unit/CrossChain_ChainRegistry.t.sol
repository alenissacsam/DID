// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {ChainRegistry} from "../../src/privacy_cross-chain/ChainRegistry.sol";
import {IChainRegistry} from "../../src/interfaces/IChainRegistry.sol";

contract CrossChain_ChainRegistryTest is Test {
    ChainRegistry cr;

    function setUp() public {
        cr = new ChainRegistry();
    }

    function test_set_chain_and_pause_unpause() public {
        cr.setChainConfig(
            101,
            "Ethereum",
            address(0xE1),
            address(0xAA),
            5,
            5_000_000,
            1e9
        );
        IChainRegistry.ChainConfig memory cfg = cr.getChainConfig(101);
        assertEq(cfg.chainId, 101);
        assertTrue(cfg.isActive);
        assertEq(
            uint256(cfg.status),
            uint256(IChainRegistry.BridgeStatus.Active)
        );

        // pause all
        cr.pauseAll("ops");
        assertFalse(cr.isChainActive(101));
        // unpause
        cr.unpauseAll();
        assertTrue(cr.isChainActive(101));
    }

    function test_set_chain_status() public {
        cr.setChainConfig(
            102,
            "Alt",
            address(0xB1),
            address(0xBB),
            0,
            2_000_000,
            2e9
        );
        cr.setChainStatus(102, IChainRegistry.BridgeStatus.Paused);
        IChainRegistry.ChainConfig memory cfg = cr.getChainConfig(102);
        assertEq(
            uint256(cfg.status),
            uint256(IChainRegistry.BridgeStatus.Paused)
        );
    }
}
