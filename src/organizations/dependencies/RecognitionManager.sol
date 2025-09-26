// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../../interfaces/IVerificationLogger.sol";
import "../../interfaces/ITrustScore.sol";
import "../../interfaces/ICertificateManager.sol";

contract RecognitionManager is ERC1155, AccessControl, ReentrancyGuard {
    bytes32 public constant BADGE_ADMIN_ROLE = keccak256("BADGE_ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    uint256 private _badgeIdCounter;

    enum BadgeType {
        Achievement,
        Milestone,
        Certification,
        Participation,
        Leadership,
        Community,
        Skill,
        Special
    }
    enum BadgeRarity {
        Common,
        Uncommon,
        Rare,
        Epic,
        Legendary
    }

    struct Badge {
        uint256 id;
        BadgeType badgeType;
        BadgeRarity rarity;
        string name;
        string description;
        string imageUri;
        string externalUrl;
        uint256 requiredTrustScore;
        uint256 maxSupply;
        uint256 currentSupply;
        bool isActive;
        bool isTransferable;
        uint256 createdAt;
        address creator;
        bytes32 criteriaHash;
        uint256 validityPeriod;
    }

    struct UserBadgeInfo {
        uint256 earnedAt;
        uint256 expiresAt;
        bool isRevoked;
        string earnReason;
        bytes32 evidenceHash;
    }

    mapping(uint256 => Badge) internal badges;
    mapping(address => mapping(uint256 => UserBadgeInfo)) public userBadges;
    mapping(address => uint256[]) public userBadgeList;
    mapping(BadgeType => uint256[]) public badgesByType;
    mapping(BadgeRarity => uint256[]) public badgesByRarity;

    ITrustScore public trustScore;
    IVerificationLogger public verificationLogger;
    ICertificateManager public certificateManager;

    event BadgeCreated(
        uint256 indexed badgeId,
        BadgeType badgeType,
        BadgeRarity rarity,
        string name,
        address creator
    );
    event BadgeAwarded(
        uint256 indexed badgeId,
        address indexed recipient,
        string reason
    );
    event BadgeRevoked(
        uint256 indexed badgeId,
        address indexed user,
        string reason
    );
    event BadgeExpired(uint256 indexed badgeId, address indexed user);
    event BadgeRenewed(
        uint256 indexed badgeId,
        address indexed user,
        uint256 newExpiryDate
    );
    event BadgeUpdated(uint256 indexed badgeId, string field);
    event AutoBadgeAwarded(
        uint256 indexed badgeId,
        address indexed recipient,
        string trigger
    );

    constructor(
        address _trustScore,
        address _verificationLogger,
        address _certificateManager
    ) ERC1155("https://api.identity.org/badge/{id}.json") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BADGE_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);

        trustScore = ITrustScore(_trustScore);
        verificationLogger = IVerificationLogger(_verificationLogger);
        certificateManager = ICertificateManager(_certificateManager);

        _createDefaultBadges();
    }

    function createBadge(
        BadgeType badgeType,
        BadgeRarity rarity,
        string memory name,
        string memory description,
        string memory imageUri,
        string memory externalUrl,
        uint256 requiredTrustScore,
        uint256 maxSupply,
        bool isTransferable,
        bytes32 criteriaHash,
        uint256 validityPeriod
    ) external onlyRole(BADGE_ADMIN_ROLE) returns (uint256) {
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(description).length > 0, "Description cannot be empty");

        _badgeIdCounter++;
        uint256 badgeId = _badgeIdCounter;

        Badge storage b = badges[badgeId];
        b.id = badgeId;
        b.badgeType = badgeType;
        b.rarity = rarity;
        b.name = name;
        b.description = description;
        b.imageUri = imageUri;
        b.externalUrl = externalUrl;
        b.requiredTrustScore = requiredTrustScore;
        b.maxSupply = maxSupply;
        b.currentSupply = 0;
        b.isActive = true;
        b.isTransferable = isTransferable;
        b.createdAt = block.timestamp;
        b.creator = msg.sender;
        b.criteriaHash = criteriaHash;
        b.validityPeriod = validityPeriod;

        badgesByType[badgeType].push(badgeId);
        badgesByRarity[rarity].push(badgeId);

        verificationLogger.logEvent(
            "BADGE_CREATED",
            msg.sender,
            keccak256(
                abi.encodePacked(
                    badgeId,
                    name,
                    uint256(badgeType),
                    uint256(rarity)
                )
            )
        );
        emit BadgeCreated(badgeId, badgeType, rarity, name, msg.sender);
        return badgeId;
    }

    function awardBadge(
        uint256 badgeId,
        address recipient,
        string memory reason,
        bytes32 evidenceHash
    ) public onlyRole(MINTER_ROLE) nonReentrant {
        Badge storage bd = badges[badgeId];
        require(bd.isActive, "Badge not active");
        require(
            bd.currentSupply < bd.maxSupply || bd.maxSupply == 0,
            "Max supply reached"
        );
        require(balanceOf(recipient, badgeId) == 0, "Badge already awarded");

        uint256 userTrustScore = trustScore.getTrustScore(recipient);
        require(
            userTrustScore >= bd.requiredTrustScore,
            "Insufficient trust score"
        );

        uint256 expiresAt = bd.validityPeriod > 0
            ? block.timestamp + bd.validityPeriod
            : 0;

        userBadges[recipient][badgeId] = UserBadgeInfo({
            earnedAt: block.timestamp,
            expiresAt: expiresAt,
            isRevoked: false,
            earnReason: reason,
            evidenceHash: evidenceHash
        });

        bd.currentSupply++;
        userBadgeList[recipient].push(badgeId);
        _mint(recipient, badgeId, 1, "");

        int256 trustScoreReward = _getBadgeTrustScore(bd.rarity);
        trustScore.updateScore(recipient, trustScoreReward, "Badge earned");

        verificationLogger.logEvent(
            "BADGE_AWARDED",
            recipient,
            keccak256(abi.encodePacked(badgeId, reason, evidenceHash))
        );
        emit BadgeAwarded(badgeId, recipient, reason);
    }

    function revokeBadge(
        uint256 badgeId,
        address user,
        string memory reason
    ) external onlyRole(BADGE_ADMIN_ROLE) {
        require(balanceOf(user, badgeId) > 0, "Badge not owned");
        UserBadgeInfo storage info = userBadges[user][badgeId];
        require(!info.isRevoked, "Badge already revoked");
        info.isRevoked = true;
        badges[badgeId].currentSupply--;

        _burn(user, badgeId, 1);
        _removeFromBadgeList(user, badgeId);

        int256 penalty = -_getBadgeTrustScore(badges[badgeId].rarity);
        trustScore.updateScore(user, penalty, "Badge revoked");

        verificationLogger.logEvent(
            "BADGE_REVOKED",
            user,
            keccak256(abi.encodePacked(badgeId, reason))
        );
        emit BadgeRevoked(badgeId, user, reason);
    }

    // ... Additional functions omitted for brevity, but use same field-by-field pattern ...

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC1155, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    // Private helpers

    function _removeFromBadgeList(address user, uint256 badgeId) private {
        uint256[] storage list = userBadgeList[user];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == badgeId) {
                list[i] = list[list.length - 1];
                list.pop();
                break;
            }
        }
    }

    function _getBadgeTrustScore(
        BadgeRarity rarity
    ) private pure returns (int256) {
        if (rarity == BadgeRarity.Legendary) return 50;
        if (rarity == BadgeRarity.Epic) return 25;
        if (rarity == BadgeRarity.Rare) return 15;
        if (rarity == BadgeRarity.Uncommon) return 8;
        return 3; // Common and default
    }

    function _createDefaultBadges() private {
        // Example of default badge creation, use fieldwise assignment...
        _badgeIdCounter++;
        Badge storage b = badges[_badgeIdCounter];
        b.id = _badgeIdCounter;
        b.badgeType = BadgeType.Milestone;
        b.rarity = BadgeRarity.Common;
        b.name = "First Steps";
        b.description = "Reached 25 trust score";
        b.imageUri = "first-steps.png";
        b.externalUrl = "";
        b.requiredTrustScore = 25;
        b.maxSupply = 0;
        b.currentSupply = 0;
        b.isActive = true;
        b.isTransferable = false;
        b.createdAt = block.timestamp;
        b.creator = msg.sender;
        b.criteriaHash = keccak256("trust_score_25");
        b.validityPeriod = 0;
        badgesByType[b.badgeType].push(_badgeIdCounter);
        badgesByRarity[b.rarity].push(_badgeIdCounter);
    }
}
