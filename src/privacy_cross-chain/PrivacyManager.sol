// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerificationLogger.sol";
import "../interfaces/IUserIdentityRegistry.sol";

contract PrivacyManager is AccessControl, ReentrancyGuard {
    bytes32 public constant PRIVACY_OFFICER_ROLE =
        keccak256("PRIVACY_OFFICER_ROLE");
    bytes32 public constant DATA_PROCESSOR_ROLE =
        keccak256("DATA_PROCESSOR_ROLE");

    enum ConsentType {
        DataProcessing, // Basic data processing consent
        Marketing, // Marketing communications
        Analytics, // Usage analytics
        ThirdPartySharing, // Sharing with third parties
        Research, // Research purposes
        LawEnforcement // Law enforcement requests
    }

    enum DataRetentionPeriod {
        OneYear, // 1 year
        ThreeYears, // 3 years
        FiveYears, // 5 years
        TenYears, // 10 years
        Indefinite // Until user requests deletion
    }

    enum RequestStatus {
        Pending, // Request submitted
        Processing, // Being processed
        Completed, // Successfully completed
        Rejected, // Request rejected
        PartiallyFulfilled // Partially completed
    }

    struct ConsentRecord {
        bool isConsented;
        uint256 consentedAt;
        uint256 updatedAt;
        string consentVersion;
        bytes32 consentHash;
        bool isWithdrawn;
        uint256 withdrawnAt;
    }

    struct DataRetentionPolicy {
        DataRetentionPeriod period;
        uint256 expiryDate;
        bool isActive;
        string description;
        bytes32 policyHash;
    }

    struct PrivacyRequest {
        uint256 id;
        address requester;
        string requestType; // "access", "portability", "erasure", "rectification", "restriction"
        string description;
        string evidenceURI;
        uint256 requestedAt;
        uint256 deadline;
        RequestStatus status;
        string responseURI;
        string rejectionReason;
        address processor;
        uint256 processedAt;
        bool isUrgent;
        bytes32 requestHash;
    }

    struct DataDisclosure {
        address user;
        string[] dataFields;
        address recipient;
        string purpose;
        uint256 disclosedAt;
        uint256 expiresAt;
        bool isActive;
        bytes32 disclosureHash;
        string legalBasis;
    }

    struct ZKProofRequest {
        address requester;
        string proofType; // "age", "citizenship", "education", "income_range", "custom"
        bytes32 criteriaHash;
        uint256 requestedAt;
        uint256 expiresAt;
        bool isCompleted;
        bytes32 proofHash;
        bool isRevoked;
    }

    mapping(address => mapping(ConsentType => ConsentRecord))
        public userConsents;
    mapping(address => DataRetentionPolicy) public userRetentionPolicies;
    mapping(uint256 => PrivacyRequest) public privacyRequests;
    mapping(address => uint256[]) public userPrivacyRequests;
    mapping(address => DataDisclosure[]) public userDataDisclosures;
    mapping(bytes32 => ZKProofRequest) public zkProofRequests;
    mapping(address => bytes32[]) public userZKProofs;
    mapping(address => bool) public gdprApplicable;
    mapping(address => string) public userJurisdiction;

    uint256 public requestCounter;
    uint256 public constant GDPR_RESPONSE_DEADLINE = 30 days;
    uint256 public constant CCPA_RESPONSE_DEADLINE = 45 days;

    IVerificationLogger public verificationLogger;
    IUserIdentityRegistry public userRegistry;

    // Privacy settings
    mapping(address => bool) public dataMinimizationEnabled;
    mapping(address => bool) public pseudonymizationEnabled;
    mapping(address => uint256) public dataAccessCount;
    mapping(address => uint256) public lastDataAccess;

    event ConsentUpdated(
        address indexed user,
        ConsentType consentType,
        bool isConsented
    );
    event ConsentWithdrawn(address indexed user, ConsentType consentType);
    event PrivacyRequestCreated(
        uint256 indexed requestId,
        address indexed requester,
        string requestType
    );
    event PrivacyRequestProcessed(
        uint256 indexed requestId,
        RequestStatus status
    );
    event DataDisclosed(
        address indexed user,
        address indexed recipient,
        string purpose
    );
    event DataErased(address indexed user, string dataType);
    event ZKProofRequested(
        bytes32 indexed proofId,
        address indexed requester,
        string proofType
    );
    event ZKProofGenerated(bytes32 indexed proofId, bytes32 proofHash);
    event RetentionPolicyUpdated(
        address indexed user,
        DataRetentionPeriod period
    );
    event DataAccessLogged(
        address indexed user,
        address indexed accessor,
        string dataType
    );

    constructor(address _verificationLogger, address _userRegistry) {
        require(
            _verificationLogger != address(0),
            "Invalid verification logger address"
        );
        require(_userRegistry != address(0), "Invalid user registry address");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PRIVACY_OFFICER_ROLE, msg.sender);
        _grantRole(DATA_PROCESSOR_ROLE, msg.sender);

        verificationLogger = IVerificationLogger(_verificationLogger);
        userRegistry = IUserIdentityRegistry(_userRegistry);
    }

    function updateConsent(
        ConsentType consentType,
        bool isConsented,
        string memory consentVersion,
        bytes32 consentHash
    ) external {
        ConsentRecord storage consent = userConsents[msg.sender][consentType];

        consent.isConsented = isConsented;
        consent.updatedAt = block.timestamp;
        consent.consentVersion = consentVersion;
        consent.consentHash = consentHash;

        if (isConsented && consent.consentedAt == 0) {
            consent.consentedAt = block.timestamp;
        }

        if (!isConsented) {
            consent.isWithdrawn = true;
            consent.withdrawnAt = block.timestamp;
        } else {
            consent.isWithdrawn = false;
            consent.withdrawnAt = 0;
        }

        verificationLogger.logEvent(
            isConsented ? "CONSENT_GRANTED" : "CONSENT_WITHDRAWN",
            msg.sender,
            keccak256(abi.encodePacked(uint256(consentType), consentHash))
        );

        if (!isConsented) {
            emit ConsentWithdrawn(msg.sender, consentType);
        } else {
            emit ConsentUpdated(msg.sender, consentType, isConsented);
        }
    }

    function createPrivacyRequest(
        string memory requestType,
        string memory description,
        string memory evidenceURI,
        bool isUrgent
    ) external returns (uint256) {
        require(bytes(requestType).length > 0, "Request type required");
        require(bytes(description).length > 0, "Description required");

        bytes32 requestTypeHash = keccak256(bytes(requestType));
        require(
            requestTypeHash == keccak256("access") ||
                requestTypeHash == keccak256("portability") ||
                requestTypeHash == keccak256("erasure") ||
                requestTypeHash == keccak256("rectification") ||
                requestTypeHash == keccak256("restriction"),
            "Invalid request type"
        );

        requestCounter++;
        uint256 requestId = requestCounter;

        // Determine deadline based on jurisdiction
        uint256 deadline = gdprApplicable[msg.sender]
            ? block.timestamp + GDPR_RESPONSE_DEADLINE
            : block.timestamp + CCPA_RESPONSE_DEADLINE;

        if (isUrgent) {
            deadline = block.timestamp + 7 days; // Urgent requests: 7 days
        }

        privacyRequests[requestId] = PrivacyRequest({
            id: requestId,
            requester: msg.sender,
            requestType: requestType,
            description: description,
            evidenceURI: evidenceURI,
            requestedAt: block.timestamp,
            deadline: deadline,
            status: RequestStatus.Pending,
            responseURI: "",
            rejectionReason: "",
            processor: address(0),
            processedAt: 0,
            isUrgent: isUrgent,
            requestHash: keccak256(
                abi.encodePacked(
                    requestId,
                    msg.sender,
                    requestType,
                    description
                )
            )
        });

        userPrivacyRequests[msg.sender].push(requestId);

        verificationLogger.logEvent(
            "PRIVACY_REQUEST_CREATED",
            msg.sender,
            keccak256(abi.encodePacked(requestId, requestType, isUrgent))
        );

        emit PrivacyRequestCreated(requestId, msg.sender, requestType);
        return requestId;
    }

    function processPrivacyRequest(
        uint256 requestId,
        RequestStatus status,
        string memory responseURI,
        string memory rejectionReason
    ) external onlyRole(DATA_PROCESSOR_ROLE) {
        PrivacyRequest storage request = privacyRequests[requestId];
        require(request.id != 0, "Request does not exist");
        require(
            request.status == RequestStatus.Pending ||
                request.status == RequestStatus.Processing,
            "Cannot process"
        );

        request.status = status;
        request.responseURI = responseURI;
        request.rejectionReason = rejectionReason;
        request.processor = msg.sender;
        request.processedAt = block.timestamp;

        // Execute the privacy action if completed
        if (status == RequestStatus.Completed) {
            _executePrivacyAction(requestId);
        }

        verificationLogger.logEvent(
            "PRIVACY_REQUEST_PROCESSED",
            request.requester,
            keccak256(abi.encodePacked(requestId, uint256(status)))
        );

        emit PrivacyRequestProcessed(requestId, status);
    }

    function setDataRetentionPolicy(
        DataRetentionPeriod period,
        string memory description
    ) external {
        uint256 expiryDate = _calculateExpiryDate(period);

        userRetentionPolicies[msg.sender] = DataRetentionPolicy({
            period: period,
            expiryDate: expiryDate,
            isActive: true,
            description: description,
            policyHash: keccak256(
                abi.encodePacked(uint256(period), description, block.timestamp)
            )
        });

        verificationLogger.logEvent(
            "RETENTION_POLICY_SET",
            msg.sender,
            keccak256(abi.encodePacked(uint256(period), expiryDate))
        );

        emit RetentionPolicyUpdated(msg.sender, period);
    }

    function disclosureData(
        address user,
        string[] memory dataFields,
        address recipient,
        string memory purpose,
        uint256 validityPeriod,
        string memory legalBasis
    ) external onlyRole(DATA_PROCESSOR_ROLE) {
        require(
            user != address(0) && recipient != address(0),
            "Invalid addresses"
        );
        require(dataFields.length > 0, "Data fields required");
        require(
            _hasConsentForDisclosure(user, purpose),
            "No consent for disclosure"
        );

        DataDisclosure memory disclosure = DataDisclosure({
            user: user,
            dataFields: dataFields,
            recipient: recipient,
            purpose: purpose,
            disclosedAt: block.timestamp,
            expiresAt: block.timestamp + validityPeriod,
            isActive: true,
            disclosureHash: keccak256(
                abi.encodePacked(user, recipient, purpose, block.timestamp)
            ),
            legalBasis: legalBasis
        });

        userDataDisclosures[user].push(disclosure);

        verificationLogger.logEvent(
            "DATA_DISCLOSED",
            user,
            keccak256(abi.encodePacked(recipient, purpose))
        );

        emit DataDisclosed(user, recipient, purpose);
    }

    function requestZKProof(
        address user,
        string memory proofType,
        bytes32 criteriaHash,
        uint256 validityPeriod
    ) external returns (bytes32) {
        require(user != address(0), "Invalid user");
        require(bytes(proofType).length > 0, "Proof type required");
        require(_hasConsentForZKProof(user), "No consent for ZK proof");

        bytes32 proofId = keccak256(
            abi.encodePacked(
                user,
                msg.sender,
                proofType,
                criteriaHash,
                block.timestamp
            )
        );

        zkProofRequests[proofId] = ZKProofRequest({
            requester: msg.sender,
            proofType: proofType,
            criteriaHash: criteriaHash,
            requestedAt: block.timestamp,
            expiresAt: block.timestamp + validityPeriod,
            isCompleted: false,
            proofHash: bytes32(0),
            isRevoked: false
        });

        userZKProofs[user].push(proofId);

        verificationLogger.logEvent(
            "ZK_PROOF_REQUESTED",
            user,
            keccak256(abi.encodePacked(proofId, proofType))
        );

        emit ZKProofRequested(proofId, msg.sender, proofType);
        return proofId;
    }

    function generateZKProof(bytes32 proofId, bytes32 proofHash) external {
        ZKProofRequest storage request = zkProofRequests[proofId];
        require(
            request.requester != address(0),
            "Proof request does not exist"
        );
        require(block.timestamp <= request.expiresAt, "Proof request expired");
        require(!request.isCompleted, "Proof already generated");

        request.isCompleted = true;
        request.proofHash = proofHash;

        verificationLogger.logEvent(
            "ZK_PROOF_GENERATED",
            msg.sender,
            keccak256(abi.encodePacked(proofId, proofHash))
        );

        emit ZKProofGenerated(proofId, proofHash);
    }

    function revokeZKProof(bytes32 proofId) external {
        ZKProofRequest storage request = zkProofRequests[proofId];
        require(
            request.requester != address(0),
            "Proof request does not exist"
        );
        require(request.isCompleted, "Proof not completed");
        require(!request.isRevoked, "Proof already revoked");

        request.isRevoked = true;

        verificationLogger.logEvent(
            "ZK_PROOF_REVOKED",
            msg.sender,
            keccak256(abi.encodePacked(proofId))
        );
    }

    function logDataAccess(
        address user,
        string memory dataType
    ) external onlyRole(DATA_PROCESSOR_ROLE) {
        dataAccessCount[user]++;
        lastDataAccess[user] = block.timestamp;

        verificationLogger.logEvent(
            "DATA_ACCESSED",
            user,
            keccak256(abi.encodePacked(msg.sender, dataType))
        );

        emit DataAccessLogged(user, msg.sender, dataType);
    }

    function enableDataMinimization() external {
        dataMinimizationEnabled[msg.sender] = true;

        verificationLogger.logEvent(
            "DATA_MINIMIZATION_ENABLED",
            msg.sender,
            bytes32(0)
        );
    }

    function enablePseudonymization() external {
        pseudonymizationEnabled[msg.sender] = true;

        verificationLogger.logEvent(
            "PSEUDONYMIZATION_ENABLED",
            msg.sender,
            bytes32(0)
        );
    }

    function setJurisdiction(
        address user,
        string memory jurisdiction
    ) external onlyRole(PRIVACY_OFFICER_ROLE) {
        userJurisdiction[user] = jurisdiction;

        bytes32 jurisdictionHash = keccak256(bytes(jurisdiction));
        gdprApplicable[user] = (jurisdictionHash == keccak256("EU") ||
            jurisdictionHash == keccak256("EEA") ||
            jurisdictionHash == keccak256("UK"));

        verificationLogger.logEvent(
            "JURISDICTION_SET",
            user,
            keccak256(bytes(jurisdiction))
        );
    }

    function checkDataRetentionExpiry(address[] memory users) external {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            DataRetentionPolicy memory policy = userRetentionPolicies[user];

            if (
                policy.isActive &&
                policy.expiryDate > 0 &&
                block.timestamp > policy.expiryDate
            ) {
                // Auto-create erasure request
                requestCounter++;
                uint256 requestId = requestCounter;

                privacyRequests[requestId] = PrivacyRequest({
                    id: requestId,
                    requester: user,
                    requestType: "erasure",
                    description: "Automatic data retention expiry",
                    evidenceURI: "",
                    requestedAt: block.timestamp,
                    deadline: block.timestamp + 7 days,
                    status: RequestStatus.Pending,
                    responseURI: "",
                    rejectionReason: "",
                    processor: address(0),
                    processedAt: 0,
                    isUrgent: true,
                    requestHash: keccak256(
                        abi.encodePacked(requestId, user, "auto_erasure")
                    )
                });

                userPrivacyRequests[user].push(requestId);
                emit PrivacyRequestCreated(requestId, user, "erasure");
            }
        }
    }

    function hasConsent(
        address user,
        ConsentType consentType
    ) external view returns (bool) {
        ConsentRecord memory consent = userConsents[user][consentType];
        return consent.isConsented && !consent.isWithdrawn;
    }

    function getPrivacyRequest(
        uint256 requestId
    )
        external
        view
        returns (
            address requester,
            string memory requestType,
            RequestStatus status,
            uint256 requestedAt,
            uint256 deadline,
            bool isUrgent
        )
    {
        PrivacyRequest memory request = privacyRequests[requestId];
        return (
            request.requester,
            request.requestType,
            request.status,
            request.requestedAt,
            request.deadline,
            request.isUrgent
        );
    }

    function getUserDataDisclosures(
        address user
    ) external view returns (uint256) {
        return userDataDisclosures[user].length;
    }

    function getUserZKProofs(
        address user
    ) external view returns (bytes32[] memory) {
        return userZKProofs[user];
    }

    function isZKProofValid(bytes32 proofId) external view returns (bool) {
        ZKProofRequest memory request = zkProofRequests[proofId];
        return
            request.isCompleted &&
            !request.isRevoked &&
            block.timestamp <= request.expiresAt;
    }

    function getUserPrivacyRequests(
        address user
    ) external view returns (uint256[] memory) {
        return userPrivacyRequests[user];
    }

    function _executePrivacyAction(uint256 requestId) private {
        PrivacyRequest memory request = privacyRequests[requestId];
        bytes32 requestTypeHash = keccak256(bytes(request.requestType));

        if (requestTypeHash == keccak256("erasure")) {
            // Execute data erasure
            _executeDataErasure(request.requester);
        } else if (requestTypeHash == keccak256("restriction")) {
            // Restrict data processing
            dataMinimizationEnabled[request.requester] = true;
        }
        // Other actions would be implemented based on request type
    }

    function _executeDataErasure(address user) private {
        // Update identity commitment to nullify old data
        bytes32 newCommitment = keccak256(
            abi.encodePacked("ERASED", user, block.timestamp)
        );
        userRegistry.updateIdentityCommitment(user, newCommitment);

        // Reset privacy settings
        delete userRetentionPolicies[user];
        dataMinimizationEnabled[user] = true;
        pseudonymizationEnabled[user] = true;

        verificationLogger.logEvent(
            "DATA_ERASED",
            user,
            keccak256(abi.encodePacked("user_data_erasure"))
        );

        emit DataErased(user, "user_data");
    }

    function _hasConsentForDisclosure(
        address user,
        string memory purpose
    ) private view returns (bool) {
        bytes32 purposeHash = keccak256(bytes(purpose));

        if (purposeHash == keccak256("marketing")) {
            return this.hasConsent(user, ConsentType.Marketing);
        } else if (purposeHash == keccak256("research")) {
            return this.hasConsent(user, ConsentType.Research);
        } else if (purposeHash == keccak256("third_party")) {
            return this.hasConsent(user, ConsentType.ThirdPartySharing);
        }

        return this.hasConsent(user, ConsentType.DataProcessing);
    }

    function _hasConsentForZKProof(address user) private view returns (bool) {
        return this.hasConsent(user, ConsentType.DataProcessing);
    }

    function _calculateExpiryDate(
        DataRetentionPeriod period
    ) private view returns (uint256) {
        if (period == DataRetentionPeriod.OneYear) {
            return block.timestamp + 365 days;
        }
        if (period == DataRetentionPeriod.ThreeYears) {
            return block.timestamp + (3 * 365 days);
        }
        if (period == DataRetentionPeriod.FiveYears) {
            return block.timestamp + (5 * 365 days);
        }
        if (period == DataRetentionPeriod.TenYears) {
            return block.timestamp + (10 * 365 days);
        }
        return 0; // Indefinite
    }
}
