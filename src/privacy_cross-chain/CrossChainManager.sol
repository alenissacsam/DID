// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import "./interfaces/IChainRegistry.sol";
import "../interfaces/ICertificateManager.sol";
import "../interfaces/ILayerZeroEndpoint.sol";

contract CrossChainManager is AccessControl, ReentrancyGuard {
    // Errors to reduce bytecode size
    error InvalidAddress();
    error InvalidParam();
    error BridgePaused();
    error ChainNotSupported();
    error BridgeNotActive();
    error FeeTooLow();
    bytes32 public constant BRIDGE_ADMIN_ROLE = keccak256("BRIDGE_ADMIN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    // Chain configuration moved to ChainRegistry to reduce bytecode size

    struct CertificatePointer {
        uint16 originChainId;
        uint256 originCertId;
        address holder;
        bytes32 certHash;
        uint256 syncedAt;
        bool isValid;
    }

    IChainRegistry public immutable chainRegistry;
    mapping(address => mapping(uint16 => uint256[])) public userCertPointers; // user => chainId => certIds
    mapping(bytes32 => CertificatePointer) public certPointers; // certHash => pointer
    mapping(bytes32 => bool) public processedMessages;

    uint256 public messageCounter;
    // activeChainIds moved to ChainRegistry

    IVerificationLogger public immutable verificationLogger;
    ICertificateManager public immutable certificateManager;
    ILayerZeroEndpoint public immutable layerZeroEndpoint;

    // Bridge settings
    uint256 public bridgeFee;
    bool public emergencyPauseEnabled;

    event CrossChainMessageSent(
        uint256 indexed messageId,
        uint16 indexed dstChainId,
        bytes32 payloadHash
    );
    event CrossChainMessageReceived(
        uint256 indexed messageId,
        uint16 indexed srcChainId,
        bool success
    );
    event CertificateSynced(
        address indexed holder,
        uint256 indexed certId,
        uint16 indexed originChainId
    );
    event ChainConfigured(
        uint16 indexed chainId,
        string chainName,
        IChainRegistry.BridgeStatus status
    );
    event BridgeStatusUpdated(
        uint16 indexed chainId,
        IChainRegistry.BridgeStatus oldStatus,
        IChainRegistry.BridgeStatus newStatus
    );
    event TrustScoreSynced(
        address indexed user,
        uint256 trustScore,
        uint16 indexed fromChainId
    );

    // Removed CrossChainError to reduce code size

    constructor(
        address _verificationLogger,
        address _certificateManager,
        address _layerZeroEndpoint,
        address _chainRegistry
    ) {
        if (_verificationLogger == address(0)) revert InvalidAddress();
        if (_certificateManager == address(0)) revert InvalidAddress();
        if (_layerZeroEndpoint == address(0)) revert InvalidAddress();
        if (_chainRegistry == address(0)) revert InvalidAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BRIDGE_ADMIN_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        certificateManager = ICertificateManager(_certificateManager);
        layerZeroEndpoint = ILayerZeroEndpoint(_layerZeroEndpoint);
        chainRegistry = IChainRegistry(_chainRegistry);

        bridgeFee = 0.001 ether;
        emergencyPauseEnabled = false;

        // chain registry owns chain configuration
    }

    function sendCrossChainMessage(
        uint16 dstChainId,
        address recipient,
        bytes calldata payload
    ) public payable nonReentrant returns (uint256) {
        if (payload.length == 0) revert InvalidParam();
        if (recipient == address(0)) revert InvalidAddress();
        if (emergencyPauseEnabled) revert BridgePaused();
        if (!chainRegistry.isChainActive(dstChainId))
            revert ChainNotSupported();
        if (msg.value < bridgeFee) revert FeeTooLow();

        messageCounter++;
        uint256 messageId = messageCounter;
        bytes32 payloadHash = keccak256(payload);

        uint256 gasLimit = chainRegistry.getChainConfig(dstChainId).maxGasLimit;

        // Send via LayerZero
        _sendViaLayerZero(dstChainId, payload, gasLimit);

        verificationLogger.logEvent(
            "CCS",
            msg.sender,
            keccak256(abi.encodePacked(messageId, dstChainId))
        );

        emit CrossChainMessageSent(messageId, dstChainId, payloadHash);
        return messageId;
    }

    function syncCertificateToChain(
        uint256 certificateId,
        uint16 dstChainId
    ) external payable {
        if (!certificateManager.verifyCertificate(certificateId))
            revert InvalidParam();

        // action code 1 = SC
        bytes memory payload = abi.encode(
            uint8(1),
            certificateId,
            msg.sender,
            _getChainId(),
            block.timestamp
        );

        this.sendCrossChainMessage{value: msg.value}(
            dstChainId,
            msg.sender,
            payload
        );
    }

    // Dedicated lean sync methods to avoid string comparisons and reduce bytecode
    function syncTrustScoreToChain(
        address user,
        uint16 dstChainId,
        uint256 score
    ) external payable onlyRole(RELAYER_ROLE) {
        bytes memory payload = abi.encode(
            uint8(2),
            user,
            score,
            block.timestamp
        );
        this.sendCrossChainMessage{value: msg.value}(dstChainId, user, payload);
    }

    function syncUserCertificatesToChain(
        address user,
        uint16 dstChainId
    ) external payable onlyRole(RELAYER_ROLE) {
        uint256[] memory certs = certificateManager.getCertificatesByHolder(
            user
        );
        bytes memory payload = abi.encode(
            uint8(3),
            user,
            certs,
            block.timestamp
        );
        this.sendCrossChainMessage{value: msg.value}(dstChainId, user, payload);
    }

    function receiveMessage(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external onlyRole(RELAYER_ROLE) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(srcChainId, srcAddress, nonce, payload)
        );
        if (processedMessages[messageHash]) revert InvalidParam();

        processedMessages[messageHash] = true;

        // Decode and execute inline to reduce code size
        uint8 action;
        (action) = abi.decode(payload, (uint8));

        if (action == 1) {
            (
                ,
                uint256 certId,
                address holder,
                uint16 originChain,
                uint256 timestamp
            ) = abi.decode(payload, (uint8, uint256, address, uint16, uint256));
            _processCertificateSync(certId, holder, originChain, timestamp);
        } else if (action == 2) {
            (, address user, uint256 trustScore, uint256 timestamp) = abi
                .decode(payload, (uint8, address, uint256, uint256));
            _processTrustScoreSync(user, trustScore, srcChainId, timestamp);
        } else if (action == 3) {
            (, address user, uint256[] memory certs, uint256 timestamp) = abi
                .decode(payload, (uint8, address, uint256[], uint256));
            for (uint256 i = 0; i < certs.length; i++) {
                _processCertificateSync(certs[i], user, srcChainId, timestamp);
            }
        }

        messageCounter++;
        uint256 messageId = messageCounter;

        verificationLogger.logEvent(
            "CCR",
            tx.origin,
            keccak256(abi.encodePacked(messageId, srcChainId))
        );
        emit CrossChainMessageReceived(messageId, srcChainId, true);
    }

    function configureSupportedChain(
        uint16 chainId,
        string calldata chainName,
        address endpoint,
        address trustedRemote,
        uint256 minConfirmations,
        uint256 maxGasLimit,
        uint256 baseFee
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        chainRegistry.setChainConfig(
            chainId,
            chainName,
            endpoint,
            trustedRemote,
            minConfirmations,
            maxGasLimit,
            baseFee
        );
        verificationLogger.logEvent(
            "CCF",
            msg.sender,
            keccak256(abi.encodePacked(chainId, chainName))
        );
        emit ChainConfigured(
            chainId,
            chainName,
            IChainRegistry.BridgeStatus.Active
        );
    }

    function updateBridgeStatus(
        uint16 chainId,
        IChainRegistry.BridgeStatus newStatus
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        IChainRegistry.ChainConfig memory cfg = chainRegistry.getChainConfig(
            chainId
        );
        if (!cfg.isActive) revert ChainNotSupported();
        IChainRegistry.BridgeStatus oldStatus = cfg.status;
        chainRegistry.setChainStatus(chainId, newStatus);

        verificationLogger.logEvent(
            "BSU",
            msg.sender,
            keccak256(
                abi.encodePacked(
                    chainId,
                    uint256(oldStatus),
                    uint256(newStatus)
                )
            )
        );

        emit BridgeStatusUpdated(chainId, oldStatus, newStatus);
    }

    function pauseAllBridges(
        string memory reason
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        emergencyPauseEnabled = true;
        chainRegistry.pauseAll(reason);
        verificationLogger.logEvent(
            "ABP",
            msg.sender,
            keccak256(bytes(reason))
        );
    }

    function unpauseAllBridges() external onlyRole(BRIDGE_ADMIN_ROLE) {
        emergencyPauseEnabled = false;
        chainRegistry.unpauseAll();
        verificationLogger.logEvent("ABU", msg.sender, bytes32(0));
    }

    // Removed retryMessage to reduce code size

    function getUserCertificatesOnChain(
        address user,
        uint16 chainId
    ) external view returns (uint256[] memory) {
        return userCertPointers[user][chainId];
    }

    function getCertificatePointer(
        bytes32 certHash
    ) external view returns (CertificatePointer memory) {
        return certPointers[certHash];
    }

    function getSupportedChains() external view returns (uint16[] memory) {
        return chainRegistry.getActiveChains();
    }

    function isBridgeActive(uint16 chainId) external view returns (bool) {
        return chainRegistry.isChainActive(chainId) && !emergencyPauseEnabled;
    }

    function estimateFee(
        uint16 dstChainId,
        bytes calldata payload
    ) external view returns (uint256) {
        IChainRegistry.ChainConfig memory config = chainRegistry.getChainConfig(
            dstChainId
        );
        uint256 gasNeeded = payload.length * 100 + config.baseFee;
        return gasNeeded + bridgeFee;
    }

    // Removed getBridgeStats to reduce code size

    // Removed try/catch decode helpers to reduce code size; decoding is done inline in receiveMessage

    function _processCertificateSync(
        uint256 certId,
        address holder,
        uint16 originChain,
        uint256 timestamp
    ) private {
        bytes32 certHash = keccak256(
            abi.encodePacked(certId, holder, originChain)
        );

        if (certPointers[certHash].syncedAt == 0) {
            certPointers[certHash] = CertificatePointer({
                originChainId: originChain,
                originCertId: certId,
                holder: holder,
                certHash: certHash,
                syncedAt: timestamp,
                isValid: true
            });

            userCertPointers[holder][originChain].push(certId);

            emit CertificateSynced(holder, certId, originChain);
        }
    }

    function _processTrustScoreSync(
        address user,
        uint256 trustScore,
        uint16 fromChainId,
        uint256 timestamp
    ) private {
        // In a full implementation, this would update a cross-chain trust score registry
        verificationLogger.logEvent(
            "TSS",
            user,
            keccak256(abi.encodePacked(trustScore, fromChainId, timestamp))
        );

        emit TrustScoreSynced(user, trustScore, fromChainId);
    }

    function _sendViaLayerZero(
        uint16 dstChainId,
        bytes memory payload,
        uint256 gasLimit
    ) private {
        IChainRegistry.ChainConfig memory config = chainRegistry.getChainConfig(
            dstChainId
        );
        if (!config.isActive) revert ChainNotSupported();
        if (config.status != IChainRegistry.BridgeStatus.Active)
            revert BridgeNotActive();
        if (payload.length == 0) revert InvalidParam();
        if (gasLimit > config.maxGasLimit) revert InvalidParam();

        bytes memory trustedRemote = abi.encodePacked(
            config.trustedRemote,
            address(this)
        );
        bytes memory adapterParams = abi.encodePacked(uint16(1), gasLimit);

        // Validate LayerZero endpoint
        if (config.endpoint == address(0)) revert InvalidAddress();

        layerZeroEndpoint.send{value: msg.value}(
            dstChainId,
            trustedRemote,
            payload,
            payable(msg.sender),
            address(0x0),
            adapterParams
        );
    }

    function _getChainId() private view returns (uint16) {
        if (block.chainid == 1) return 101; // Ethereum
        if (block.chainid == 137) return 109; // Polygon
        if (block.chainid == 56) return 102; // BSC
        if (block.chainid == 43114) return 106; // Avalanche
        if (block.chainid == 42161) return 110; // Arbitrum
        return 10001; // Testnet/Unknown
    }

    // removed _initializeSupportedChains

    function setBridgeFee(uint256 newFee) external onlyRole(BRIDGE_ADMIN_ROLE) {
        bridgeFee = newFee;
    }

    error NoFees();
    error WithdrawFailed();

    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert InvalidAddress();
        uint256 balance = address(this).balance;
        if (balance == 0) revert NoFees();

        (bool success, ) = recipient.call{value: balance}("");
        if (!success) revert WithdrawFailed();
    }

    receive() external payable {}
}
