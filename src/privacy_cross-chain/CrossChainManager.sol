// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";

interface ICertificateManager {
    function getCertificatesByHolder(address holder) external view returns (uint256[] memory);

    function verifyCertificate(uint256 certificateId) external view returns (bool);
}

interface ILayerZeroEndpoint {
    function send(
        uint16 _dstChainId,
        bytes calldata _destination,
        bytes calldata _payload,
        address _refundAddress,
        address _zroPaymentAddress,
        bytes calldata _adapterParams
    ) external payable;

    function receivePayload(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        address _dstAddress,
        uint64 _nonce,
        uint256 _gasLimit,
        bytes calldata _payload
    ) external;
}

contract CrossChainManager is AccessControl, ReentrancyGuard {
    bytes32 public constant BRIDGE_ADMIN_ROLE = keccak256("BRIDGE_ADMIN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    enum MessageType {
        CertificateSync, // Sync certificate data
        TrustScoreSync, // Sync trust scores
        IdentitySync, // Sync identity updates
        BadgeSync, // Sync badge awards
        GovernanceSync // Sync governance decisions

    }

    enum BridgeStatus {
        Active,
        Paused,
        Deprecated
    }

    struct CrossChainMessage {
        uint256 id;
        uint16 srcChainId;
        uint16 dstChainId;
        MessageType msgType;
        address sender;
        address recipient;
        bytes payload;
        bytes32 payloadHash;
        uint256 timestamp;
        uint64 nonce;
        bool isProcessed;
        uint256 gasLimit;
        uint256 fee;
    }

    struct ChainConfig {
        uint16 chainId;
        string chainName;
        address endpoint;
        address trustedRemote;
        BridgeStatus status;
        uint256 minConfirmations;
        uint256 maxGasLimit;
        uint256 baseFee;
        bool isActive;
        uint256 lastSyncTime;
    }

    struct CertificatePointer {
        uint16 originChainId;
        uint256 originCertId;
        address holder;
        bytes32 certHash;
        uint256 syncedAt;
        bool isValid;
    }

    mapping(uint256 => CrossChainMessage) public crossChainMessages;
    mapping(uint16 => ChainConfig) public supportedChains;
    mapping(address => mapping(uint16 => uint256[])) public userCertPointers; // user => chainId => certIds
    mapping(bytes32 => CertificatePointer) public certPointers; // certHash => pointer
    mapping(uint16 => uint64) public chainNonces;
    mapping(bytes32 => bool) public processedMessages;

    uint256 public messageCounter;
    uint16[] public activeChainIds;

    IVerificationLogger public verificationLogger;
    ICertificateManager public certificateManager;
    ILayerZeroEndpoint public layerZeroEndpoint;

    // Bridge settings
    uint256 public bridgeFee;
    uint256 public maxRetryAttempts;
    bool public emergencyPauseEnabled;

    event CrossChainMessageSent(
        uint256 indexed messageId, uint16 indexed dstChainId, MessageType msgType, bytes32 payloadHash
    );
    event CrossChainMessageReceived(
        uint256 indexed messageId, uint16 indexed srcChainId, MessageType msgType, bool success
    );
    event CertificateSynced(address indexed holder, uint256 indexed certId, uint16 indexed originChainId);
    event ChainConfigured(uint16 indexed chainId, string chainName, BridgeStatus status);
    event BridgeStatusUpdated(uint16 indexed chainId, BridgeStatus oldStatus, BridgeStatus newStatus);
    event TrustScoreSynced(address indexed user, uint256 trustScore, uint16 indexed fromChainId);
    event CrossChainError(uint256 indexed messageId, string error);

    constructor(address _verificationLogger, address _certificateManager, address _layerZeroEndpoint) {
        require(_verificationLogger != address(0), "Invalid verification logger");
        require(_certificateManager != address(0), "Invalid certificate manager");
        require(_layerZeroEndpoint != address(0), "Invalid LayerZero endpoint");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BRIDGE_ADMIN_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        certificateManager = ICertificateManager(_certificateManager);
        layerZeroEndpoint = ILayerZeroEndpoint(_layerZeroEndpoint);

        bridgeFee = 0.001 ether;
        maxRetryAttempts = 3;
        emergencyPauseEnabled = false;

        _initializeSupportedChains();
    }

    function sendCrossChainMessage(uint16 dstChainId, MessageType msgType, address recipient, bytes memory payload)
        public
        payable
        nonReentrant
        returns (uint256)
    {
        require(payload.length > 0, "Empty payload");
        require(recipient != address(0), "Invalid recipient");
        require(!emergencyPauseEnabled, "Bridge paused");
        require(supportedChains[dstChainId].isActive, "Chain not supported");
        require(supportedChains[dstChainId].status == BridgeStatus.Active, "Bridge not active");
        require(msg.value >= bridgeFee, "Insufficient bridge fee");

        messageCounter++;
        uint256 messageId = messageCounter;
        bytes32 payloadHash = keccak256(payload);

        chainNonces[dstChainId]++;

        CrossChainMessage storage message = crossChainMessages[messageId];
        message.id = messageId;
        message.srcChainId = _getChainId();
        message.dstChainId = dstChainId;
        message.msgType = msgType;
        message.sender = msg.sender;
        message.recipient = recipient;
        message.payload = payload;
        message.payloadHash = payloadHash;
        message.timestamp = block.timestamp;
        message.nonce = chainNonces[dstChainId];
        message.gasLimit = supportedChains[dstChainId].maxGasLimit;
        message.fee = msg.value;

        // Send via LayerZero
        _sendViaLayerZero(dstChainId, payload, message.gasLimit);

        verificationLogger.logEvent(
            "CROSS_CHAIN_MESSAGE_SENT", msg.sender, keccak256(abi.encodePacked(messageId, dstChainId, uint256(msgType)))
        );

        emit CrossChainMessageSent(messageId, dstChainId, msgType, payloadHash);
        return messageId;
    }

    function syncCertificateToChain(uint256 certificateId, uint16 dstChainId) external payable {
        require(certificateManager.verifyCertificate(certificateId), "Certificate not valid");

        bytes memory payload = abi.encode("SYNC_CERTIFICATE", certificateId, msg.sender, _getChainId(), block.timestamp);

        sendCrossChainMessage(dstChainId, MessageType.CertificateSync, msg.sender, payload);
    }

    function syncUserDataToChain(address user, uint16 dstChainId, string memory dataType)
        external
        payable
        onlyRole(RELAYER_ROLE)
    {
        bytes memory payload;

        if (keccak256(bytes(dataType)) == keccak256("trust_score")) {
            // Placeholder for trust score data
            payload = abi.encode(
                "SYNC_TRUST_SCORE",
                user,
                250, // placeholder trust score
                block.timestamp
            );
        } else if (keccak256(bytes(dataType)) == keccak256("certificates")) {
            uint256[] memory certs = certificateManager.getCertificatesByHolder(user);
            payload = abi.encode("SYNC_USER_CERTIFICATES", user, certs, block.timestamp);
        }

        sendCrossChainMessage(dstChainId, MessageType.IdentitySync, user, payload);
    }

    function receiveMessage(uint16 srcChainId, bytes memory srcAddress, uint64 nonce, bytes memory payload)
        external
        onlyRole(RELAYER_ROLE)
    {
        bytes32 messageHash = keccak256(abi.encodePacked(srcChainId, srcAddress, nonce, payload));
        require(!processedMessages[messageHash], "Message already processed");

        processedMessages[messageHash] = true;

        bool success = _processIncomingMessage(srcChainId, payload);

        messageCounter++;
        uint256 messageId = messageCounter;

        verificationLogger.logEvent(
            "CROSS_CHAIN_MESSAGE_RECEIVED", tx.origin, keccak256(abi.encodePacked(messageId, srcChainId, success))
        );

        emit CrossChainMessageReceived(messageId, srcChainId, MessageType.CertificateSync, success);
    }

    function configureSupportedChain(
        uint16 chainId,
        string memory chainName,
        address endpoint,
        address trustedRemote,
        uint256 minConfirmations,
        uint256 maxGasLimit,
        uint256 baseFee
    ) external onlyRole(BRIDGE_ADMIN_ROLE) {
        require(chainId > 0, "Invalid chain ID");
        require(bytes(chainName).length > 0, "Empty chain name");
        require(endpoint != address(0), "Invalid endpoint");
        require(trustedRemote != address(0), "Invalid trusted remote");
        require(maxGasLimit > 0, "Invalid gas limit");

        bool isNewChain = !supportedChains[chainId].isActive;

        supportedChains[chainId] = ChainConfig({
            chainId: chainId,
            chainName: chainName,
            endpoint: endpoint,
            trustedRemote: trustedRemote,
            status: BridgeStatus.Active,
            minConfirmations: minConfirmations,
            maxGasLimit: maxGasLimit,
            baseFee: baseFee,
            isActive: true,
            lastSyncTime: block.timestamp
        });

        if (isNewChain) {
            activeChainIds.push(chainId);
        }

        verificationLogger.logEvent("CHAIN_CONFIGURED", msg.sender, keccak256(abi.encodePacked(chainId, chainName)));

        emit ChainConfigured(chainId, chainName, BridgeStatus.Active);
    }

    function updateBridgeStatus(uint16 chainId, BridgeStatus newStatus) external onlyRole(BRIDGE_ADMIN_ROLE) {
        require(supportedChains[chainId].isActive, "Chain not configured");

        BridgeStatus oldStatus = supportedChains[chainId].status;
        supportedChains[chainId].status = newStatus;

        verificationLogger.logEvent(
            "BRIDGE_STATUS_UPDATED",
            msg.sender,
            keccak256(abi.encodePacked(chainId, uint256(oldStatus), uint256(newStatus)))
        );

        emit BridgeStatusUpdated(chainId, oldStatus, newStatus);
    }

    function pauseAllBridges(string memory reason) external onlyRole(BRIDGE_ADMIN_ROLE) {
        emergencyPauseEnabled = true;

        for (uint256 i = 0; i < activeChainIds.length; i++) {
            supportedChains[activeChainIds[i]].status = BridgeStatus.Paused;
        }

        verificationLogger.logEvent("ALL_BRIDGES_PAUSED", msg.sender, keccak256(bytes(reason)));
    }

    function unpauseAllBridges() external onlyRole(BRIDGE_ADMIN_ROLE) {
        emergencyPauseEnabled = false;

        for (uint256 i = 0; i < activeChainIds.length; i++) {
            if (supportedChains[activeChainIds[i]].status == BridgeStatus.Paused) {
                supportedChains[activeChainIds[i]].status = BridgeStatus.Active;
            }
        }

        verificationLogger.logEvent("ALL_BRIDGES_UNPAUSED", msg.sender, bytes32(0));
    }

    function retryMessage(uint256 messageId) external payable {
        CrossChainMessage storage message = crossChainMessages[messageId];
        require(message.id != 0, "Message does not exist");
        require(message.sender == msg.sender, "Not message sender");
        require(!message.isProcessed, "Message already processed");
        require(msg.value >= message.fee, "Insufficient retry fee");

        _sendViaLayerZero(message.dstChainId, message.payload, message.gasLimit);

        verificationLogger.logEvent("MESSAGE_RETRIED", msg.sender, keccak256(abi.encodePacked(messageId)));
    }

    function getUserCertificatesOnChain(address user, uint16 chainId) external view returns (uint256[] memory) {
        return userCertPointers[user][chainId];
    }

    function getCertificatePointer(bytes32 certHash) external view returns (CertificatePointer memory) {
        return certPointers[certHash];
    }

    function getSupportedChains() external view returns (uint16[] memory) {
        return activeChainIds;
    }

    function getChainConfig(uint16 chainId) external view returns (ChainConfig memory) {
        return supportedChains[chainId];
    }

    function isBridgeActive(uint16 chainId) external view returns (bool) {
        return supportedChains[chainId].isActive && supportedChains[chainId].status == BridgeStatus.Active
            && !emergencyPauseEnabled;
    }

    function estimateFee(uint16 dstChainId, bytes memory payload) external view returns (uint256) {
        ChainConfig memory config = supportedChains[dstChainId];
        uint256 gasNeeded = payload.length * 100 + config.baseFee;
        return gasNeeded + bridgeFee;
    }

    function getBridgeStats()
        external
        view
        returns (uint256 totalMessages, uint256 activeChains, uint256 pausedBridges, uint256 totalVolume)
    {
        totalMessages = messageCounter;
        activeChains = activeChainIds.length;

        uint256 paused = 0;
        for (uint256 i = 0; i < activeChainIds.length; i++) {
            if (supportedChains[activeChainIds[i]].status == BridgeStatus.Paused) {
                paused++;
            }
        }
        pausedBridges = paused;

        // totalVolume would require additional tracking
        totalVolume = 0;
    }

    function _processIncomingMessage(uint16 srcChainId, bytes memory payload) private returns (bool) {
        try this._decodeAndExecuteMessage(srcChainId, payload) {
            return true;
        } catch Error(string memory error) {
            verificationLogger.logEvent("CROSS_CHAIN_ERROR", tx.origin, keccak256(bytes(error)));
            emit CrossChainError(messageCounter, error);
            return false;
        } catch {
            verificationLogger.logEvent("CROSS_CHAIN_ERROR", tx.origin, keccak256("Unknown error"));
            emit CrossChainError(messageCounter, "Unknown error");
            return false;
        }
    }

    function _decodeAndExecuteMessage(uint16 srcChainId, bytes memory payload) external {
        require(msg.sender == address(this), "Internal function only");

        string memory action;
        (action) = abi.decode(payload, (string));
        bytes32 actionHash;
        assembly {
            actionHash := keccak256(add(action, 0x20), mload(action))
        }

        if (actionHash == keccak256("SYNC_CERTIFICATE")) {
            (, uint256 certId, address holder, uint16 originChain, uint256 timestamp) =
                abi.decode(payload, (string, uint256, address, uint16, uint256));

            _processCertificateSync(certId, holder, originChain, timestamp);
        } else if (actionHash == keccak256("SYNC_TRUST_SCORE")) {
            (, address user, uint256 trustScore, uint256 timestamp) =
                abi.decode(payload, (string, address, uint256, uint256));

            _processTrustScoreSync(user, trustScore, srcChainId, timestamp);
        } else if (actionHash == keccak256("SYNC_USER_CERTIFICATES")) {
            (, address user, uint256[] memory certs, uint256 timestamp) =
                abi.decode(payload, (string, address, uint256[], uint256));

            for (uint256 i = 0; i < certs.length; i++) {
                _processCertificateSync(certs[i], user, srcChainId, timestamp);
            }
        }
    }

    function _processCertificateSync(uint256 certId, address holder, uint16 originChain, uint256 timestamp) private {
        bytes32 certHash = keccak256(abi.encodePacked(certId, holder, originChain));

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

    function _processTrustScoreSync(address user, uint256 trustScore, uint16 fromChainId, uint256 timestamp) private {
        // In a full implementation, this would update a cross-chain trust score registry
        verificationLogger.logEvent(
            "TRUST_SCORE_SYNCED", user, keccak256(abi.encodePacked(trustScore, fromChainId, timestamp))
        );

        emit TrustScoreSynced(user, trustScore, fromChainId);
    }

    function _sendViaLayerZero(uint16 dstChainId, bytes memory payload, uint256 gasLimit) private {
        ChainConfig memory config = supportedChains[dstChainId];
        require(config.isActive, "Chain not active");
        require(config.status == BridgeStatus.Active, "Bridge not active");
        require(payload.length > 0, "Empty payload");
        require(gasLimit <= config.maxGasLimit, "Gas limit too high");

        bytes memory trustedRemote = abi.encodePacked(config.trustedRemote, address(this));
        bytes memory adapterParams = abi.encodePacked(uint16(1), gasLimit);

        // Validate LayerZero endpoint
        require(config.endpoint != address(0), "Invalid endpoint");

        layerZeroEndpoint.send{value: msg.value}(
            dstChainId, trustedRemote, payload, payable(msg.sender), address(0x0), adapterParams
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

    function _initializeSupportedChains() private {
        // Polygon
        supportedChains[109] = ChainConfig({
            chainId: 109,
            chainName: "Polygon",
            endpoint: address(0x3c2269811836af69497E5F486A85D7316753cf62),
            trustedRemote: address(0),
            status: BridgeStatus.Active,
            minConfirmations: 20,
            maxGasLimit: 200000,
            baseFee: 0.0001 ether,
            isActive: true,
            lastSyncTime: block.timestamp
        });
        activeChainIds.push(109);

        // Ethereum
        supportedChains[101] = ChainConfig({
            chainId: 101,
            chainName: "Ethereum",
            endpoint: address(0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675),
            trustedRemote: address(0),
            status: BridgeStatus.Active,
            minConfirmations: 12,
            maxGasLimit: 500000,
            baseFee: 0.01 ether,
            isActive: true,
            lastSyncTime: block.timestamp
        });
        activeChainIds.push(101);

        // BSC
        supportedChains[102] = ChainConfig({
            chainId: 102,
            chainName: "BSC",
            endpoint: address(0x3c2269811836af69497E5F486A85D7316753cf62),
            trustedRemote: address(0),
            status: BridgeStatus.Active,
            minConfirmations: 15,
            maxGasLimit: 300000,
            baseFee: 0.001 ether,
            isActive: true,
            lastSyncTime: block.timestamp
        });
        activeChainIds.push(102);
    }

    function setBridgeFee(uint256 newFee) external onlyRole(BRIDGE_ADMIN_ROLE) {
        bridgeFee = newFee;
    }

    function withdrawFees(address payable recipient) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(recipient != address(0), "Invalid recipient");
        uint256 balance = address(this).balance;
        require(balance > 0, "No fees to withdraw");

        (bool success,) = recipient.call{value: balance}("");
        require(success, "Withdrawal failed");
    }

    receive() external payable {}
}
