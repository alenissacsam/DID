// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {CrossChainManager} from "../../src/privacy_cross-chain/CrossChainManager.sol";
import {ChainRegistry} from "../../src/privacy_cross-chain/ChainRegistry.sol";
import {ICertificateManager} from "../../src/interfaces/ICertificateManager.sol";
import {IVerificationLogger} from "../../src/interfaces/IVerificationLogger.sol";
import {IChainRegistry} from "../../src/interfaces/IChainRegistry.sol";

contract MockLogger is IVerificationLogger {
    event Logged(string t, address u, bytes32 h);

    function logEvent(
        string memory eventType,
        address user,
        bytes32 dataHash
    ) external override {
        emit Logged(eventType, user, dataHash);
    }
}

contract MockEndpoint {
    event Sent(uint16 dst, bytes payload, uint256 value);

    function send(
        uint16 dstChainId,
        bytes calldata,
        bytes calldata payload,
        address payable /*refundAddress*/,
        address /*zroPaymentAddress*/,
        bytes calldata
    ) external payable {
        emit Sent(dstChainId, payload, msg.value);
        // refund logic not needed for tests
    }
}

contract MockCertificateManager is ICertificateManager {
    mapping(uint256 => bool) public valid;
    mapping(address => uint256[]) internal certs;

    function issue(address a, uint256 id) external {
        valid[id] = true;
        certs[a].push(id);
    }

    function verifyCertificate(uint256 id) external view returns (bool) {
        return valid[id];
    }

    function getCertificatesByHolder(
        address holder
    ) external view returns (uint256[] memory) {
        return certs[holder];
    }

    function grantRole(bytes32, address) external {}

    function revokeRole(bytes32, address) external {}
}

contract CrossChain_CrossChainManagerTest is Test {
    CrossChainManager mgr;
    ChainRegistry cr;
    MockLogger logger;
    MockEndpoint endpoint;
    MockCertificateManager certMgr;
    address admin = address(this);

    function setUp() public {
        cr = new ChainRegistry();
        logger = new MockLogger();
        endpoint = new MockEndpoint();
        certMgr = new MockCertificateManager();
        // configure a destination chain on registry
        cr.setChainConfig(
            101,
            "Ethereum",
            address(endpoint),
            address(0xCC),
            0,
            5_000_000,
            1e9
        );
        mgr = new CrossChainManager(
            address(logger),
            address(certMgr),
            address(endpoint),
            address(cr)
        );
        // grant roles required for tests
        bytes32 RELAYER_ROLE = keccak256("RELAYER_ROLE");
        mgr.grantRole(RELAYER_ROLE, admin);
        // CrossChainManager itself must have BRIDGE_ADMIN_ROLE on the ChainRegistry to pause/unpause
        bytes32 BRIDGE_ADMIN_ROLE = cr.BRIDGE_ADMIN_ROLE();
        cr.grantRole(BRIDGE_ADMIN_ROLE, address(mgr));
    }

    function test_send_cross_chain_message() public {
        uint256 fee = mgr.bridgeFee();
        bytes memory payload = abi.encode(uint8(9), address(this));
        uint256 id = mgr.sendCrossChainMessage{value: fee}(
            101,
            address(this),
            payload
        );
        assertEq(id, 1);
    }

    function test_sync_certificate_and_receive() public {
        // issue cert id 7 to self
        certMgr.issue(address(this), 7);
        uint256 fee = mgr.bridgeFee();
        mgr.syncCertificateToChain{value: fee}(7, 101);
        // simulate receive of certificate sync payload (action 1)
        uint16 originChain = uint16(10001);
        bytes memory payload = abi.encode(
            uint8(1),
            7,
            address(this),
            originChain,
            block.timestamp
        );
        bytes memory srcAddr = abi.encodePacked(address(this));
        mgr.receiveMessage(uint16(101), srcAddr, 1, payload);
        // verify pointer
        bytes32 hash = keccak256(
            abi.encodePacked(uint256(7), address(this), originChain)
        );
        CrossChainManager.CertificatePointer memory ptr = mgr
            .getCertificatePointer(hash);
        assertTrue(ptr.isValid);
        assertEq(ptr.originCertId, 7);
    }

    function test_pause_and_unpause() public {
        mgr.pauseAllBridges("risk");
        // ensure registry status is paused
        IChainRegistry.ChainConfig memory cfg = cr.getChainConfig(101);
        assertEq(
            uint256(cfg.status),
            uint256(IChainRegistry.BridgeStatus.Paused)
        );
        // confirm emergency flag
        assertTrue(mgr.emergencyPauseEnabled(), "pause flag not set");
        uint256 fee = mgr.bridgeFee();
        vm.expectRevert(CrossChainManager.BridgePaused.selector);
        mgr.sendCrossChainMessage{value: fee}(
            101,
            address(this),
            abi.encode(uint8(1))
        );
        mgr.unpauseAllBridges();
        cfg = cr.getChainConfig(101);
        assertEq(
            uint256(cfg.status),
            uint256(IChainRegistry.BridgeStatus.Active)
        );
    }

    function test_configure_supported_chain() public {
        // configure a new chain via manager (ensures manager has registry role)
        mgr.configureSupportedChain(
            202,
            "TestChain",
            address(endpoint),
            address(0xAB),
            0,
            3_000_000,
            5e8
        );
        IChainRegistry.ChainConfig memory cfg = cr.getChainConfig(202);
        assertEq(cfg.chainId, 202);
        assertEq(cfg.maxGasLimit, 3_000_000);
        assertEq(cfg.baseFee, 5e8);
        assertTrue(cfg.isActive);
    }

    function test_update_bridge_status() public {
        // manager updates status of pre-configured chain 101
        mgr.updateBridgeStatus(101, IChainRegistry.BridgeStatus.Paused);
        IChainRegistry.ChainConfig memory cfg = cr.getChainConfig(101);
        assertEq(
            uint256(cfg.status),
            uint256(IChainRegistry.BridgeStatus.Paused)
        );
        mgr.updateBridgeStatus(101, IChainRegistry.BridgeStatus.Active);
        cfg = cr.getChainConfig(101);
        assertEq(
            uint256(cfg.status),
            uint256(IChainRegistry.BridgeStatus.Active)
        );
    }

    function test_estimate_fee() public view {
        bytes memory payload = abi.encode(uint8(9), address(this));
        uint256 quote = mgr.estimateFee(101, payload);
        IChainRegistry.ChainConfig memory cfg = cr.getChainConfig(101);
        uint256 expected = (payload.length * 100 + cfg.baseFee) +
            mgr.bridgeFee();
        assertEq(quote, expected);
    }

    function test_set_bridge_fee_and_withdraw() public {
        // change fee
        mgr.setBridgeFee(0.002 ether);
        assertEq(mgr.bridgeFee(), 0.002 ether);
        // fund manager by sending ether (manager has receive)
        vm.deal(address(this), 2 ether);
        (bool ok, ) = address(mgr).call{value: 1 ether}("");
        assertTrue(ok);
        uint256 before = address(this).balance;
        mgr.withdrawFees(payable(address(this)));
        assertGt(address(this).balance, before);
        // no fees left
        vm.expectRevert(CrossChainManager.NoFees.selector);
        mgr.withdrawFees(payable(address(this)));
    }

    // Allow test contract to receive withdrawn ETH
    receive() external payable {}

    function test_trust_score_sync_and_receive() public {
        uint256 fee = mgr.bridgeFee();
        mgr.syncTrustScoreToChain{value: fee}(address(this), 101, 42);
        bytes memory payload = abi.encode(
            uint8(2),
            address(this),
            uint256(99),
            block.timestamp
        );
        bytes memory srcAddr = abi.encodePacked(address(this));
        // action 2 receive
        mgr.receiveMessage(uint16(101), srcAddr, 2, payload);
        bytes32 messageHash = keccak256(
            abi.encodePacked(uint16(101), srcAddr, uint64(2), payload)
        );
        assertTrue(mgr.processedMessages(messageHash));
    }

    function test_sync_user_certificates_and_receive() public {
        certMgr.issue(address(this), 11);
        certMgr.issue(address(this), 12);
        uint256 fee = mgr.bridgeFee();
        mgr.syncUserCertificatesToChain{value: fee}(address(this), 101);
        uint256[] memory certsLocal = new uint256[](2);
        certsLocal[0] = 11;
        certsLocal[1] = 12;
        bytes memory payload = abi.encode(
            uint8(3),
            address(this),
            certsLocal,
            block.timestamp
        );
        bytes memory srcAddr = abi.encodePacked(address(this));
        mgr.receiveMessage(uint16(101), srcAddr, 3, payload);
        for (uint256 i = 0; i < certsLocal.length; i++) {
            bytes32 h = keccak256(
                abi.encodePacked(certsLocal[i], address(this), uint16(101))
            );
            CrossChainManager.CertificatePointer memory ptr = mgr
                .getCertificatePointer(h);
            // since originChain for action 3 uses srcChainId (101)
            assertTrue(ptr.isValid);
            assertEq(ptr.originCertId, certsLocal[i]);
        }
    }
}
