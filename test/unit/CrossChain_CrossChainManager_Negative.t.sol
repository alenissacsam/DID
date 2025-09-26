// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {CrossChainManager} from "../../src/privacy_cross-chain/CrossChainManager.sol";
import {ChainRegistry} from "../../src/privacy_cross-chain/ChainRegistry.sol";
import {IChainRegistry} from "../../src/interfaces/IChainRegistry.sol";
import {IVerificationLogger} from "../../src/interfaces/IVerificationLogger.sol";
import {ICertificateManager} from "../../src/interfaces/ICertificateManager.sol";

contract MockLogger2 is IVerificationLogger {
    function logEvent(string memory, address, bytes32) external override {}
}

contract MockEndpoint2 {
    function send(
        uint16,
        bytes calldata,
        bytes calldata,
        address payable,
        address,
        bytes calldata
    ) external payable {}
}

contract MockCertMgr2 is ICertificateManager {
    mapping(uint256 => bool) public valid;

    function issue(uint256 id) external {
        valid[id] = true;
    }

    function verifyCertificate(uint256 id) external view returns (bool) {
        return valid[id];
    }

    function getCertificatesByHolder(
        address
    ) external pure returns (uint256[] memory arr) {
        return arr;
    }

    function grantRole(bytes32, address) external {}

    function revokeRole(bytes32, address) external {}
}

contract CrossChain_CrossChainManager_Negative is Test {
    CrossChainManager mgr;
    ChainRegistry cr;
    MockLogger2 logger;
    MockEndpoint2 ep;
    MockCertMgr2 cert;
    address admin = address(this);
    bytes32 constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    function setUp() public {
        cr = new ChainRegistry();
        logger = new MockLogger2();
        ep = new MockEndpoint2();
        cert = new MockCertMgr2();
        // Configure one active chain (200)
        cr.setChainConfig(
            200,
            "TestChain",
            address(ep),
            address(0xBEEF),
            0,
            3_000_000,
            1e9
        );
        mgr = new CrossChainManager(
            address(logger),
            address(cert),
            address(ep),
            address(cr)
        );
        mgr.grantRole(RELAYER_ROLE, admin);
        // Give manager admin role on registry to modify status
        cr.grantRole(cr.BRIDGE_ADMIN_ROLE(), address(mgr));
    }

    function test_fee_too_low_reverts() public {
        bytes memory payload = abi.encode(uint8(9), address(this));
        vm.expectRevert(CrossChainManager.FeeTooLow.selector);
        mgr.sendCrossChainMessage{value: 0}(200, address(this), payload);
    }

    function test_chain_not_supported_reverts() public {
        bytes memory payload = abi.encode(uint8(9), address(this));
        // chain 201 not configured => isChainActive false so ChainNotSupported
        bool isActive = cr.isChainActive(201);
        assertFalse(isActive, "diagnostic: chain 201 unexpectedly active");
        uint256 fee = mgr.bridgeFee();
        vm.expectRevert(CrossChainManager.ChainNotSupported.selector);
        mgr.sendCrossChainMessage{value: fee}(201, address(this), payload);
    }

    function test_emergency_pause_reverts() public {
        // trigger global emergency pause to exercise BridgePaused branch (emergencyPauseEnabled)
        vm.prank(address(this));
        mgr.pauseAllBridges("maint");
        // diagnostic assertions
        assertTrue(
            mgr.emergencyPauseEnabled(),
            "diagnostic: pause flag not set"
        );
        bytes memory payload = abi.encode(uint8(9), address(this));
        uint256 fee = mgr.bridgeFee();
        vm.expectRevert(CrossChainManager.BridgePaused.selector);
        mgr.sendCrossChainMessage{value: fee}(200, address(this), payload);
    }

    function test_duplicate_receive_reverts() public {
        // create payload + receive once
        bytes memory payload = abi.encode(
            uint8(2),
            address(this),
            uint256(10),
            block.timestamp
        );
        bytes memory srcAddr = abi.encodePacked(address(this));
        // first receive OK
        mgr.receiveMessage(200, srcAddr, 1, payload);
        // second with same params should revert InvalidParam (processed)
        vm.expectRevert(CrossChainManager.InvalidParam.selector);
        mgr.receiveMessage(200, srcAddr, 1, payload);
    }
}
