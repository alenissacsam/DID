// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./BaseAccountModule.sol";
import "../../interfaces/IVerificationLogger.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SessionKeyModule is BaseAccountModule {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct SessionKey {
        address keyAddress;
        uint256 validUntil;
        uint256 dailyLimit;
        bytes32 dAppHash;
        string dAppDomain;
        bool isActive;
        uint256 totalUsed;
        uint256 dailyUsed;
        uint256 lastResetDay;
        bytes4[] allowedSelectors; // Direct selector storage (gas efficient)
    }

    IVerificationLogger public immutable logger;
    mapping(address => SessionKey) public sessionKeys;
    address[] public sessionKeysList;
    mapping(string => address) public domainToKey;

    event SessionKeyAdded(
        address indexed sessionKey,
        string indexed dAppDomain,
        uint256 validUntil
    );
    event SessionKeyRevoked(address indexed sessionKey, string reason);
    event SessionKeyUsed(
        address indexed sessionKey,
        string indexed dAppDomain,
        uint256 gasUsed,
        bytes4 selector
    );
    event SessionKeyReplaced(
        string indexed dAppDomain,
        address oldKey,
        address newKey
    );

    // Custom errors
    error ErrorInvalidDomain();
    error ErrorInvalidKey();
    error ErrorKeyExists();
    error ErrorInactiveOrExpired();
    error ErrorDomainMismatch();
    error ErrorBadSignature();
    error ErrorFnNotAllowed();
    error ErrorDailyLimit();
    error ErrorCallFailed();

    constructor(address _account, address _logger) BaseAccountModule(_account) {
        logger = IVerificationLogger(_logger);
    }

    function moduleId() external pure returns (bytes32) {
        return keccak256("SESSION_KEY_MODULE_V1");
    }

    function createSessionKey(
        address keyAddress,
        string memory dAppDomain,
        uint256 validFor,
        uint256 dailyLimit,
        bytes4[] memory allowedSelectors
    ) external onlyAccount returns (address sessionKeyAddress) {
        if (bytes(dAppDomain).length == 0) revert ErrorInvalidDomain();
        if (keyAddress == address(0)) revert ErrorInvalidKey();
        if (sessionKeys[keyAddress].keyAddress != address(0))
            revert ErrorKeyExists();

        // Overwrite domain: if a key already mapped to domain, revoke old silently
        address old = domainToKey[dAppDomain];
        if (old != address(0)) {
            sessionKeys[old].isActive = false;
            emit SessionKeyReplaced(dAppDomain, old, keyAddress);
        }

        sessionKeyAddress = keyAddress;
        SessionKey storage sk = sessionKeys[sessionKeyAddress];
        sk.keyAddress = keyAddress;
        sk.validUntil = block.timestamp + validFor;
        sk.dailyLimit = dailyLimit;
        sk.dAppHash = keccak256(abi.encodePacked(dAppDomain));
        sk.dAppDomain = dAppDomain;
        sk.isActive = true;
        sk.allowedSelectors = allowedSelectors;
        sk.lastResetDay = block.timestamp / 1 days;
        sessionKeysList.push(sessionKeyAddress);
        domainToKey[dAppDomain] = sessionKeyAddress;

        logger.logEvent(
            "SESSION_KEY_CREATED",
            account,
            keccak256(abi.encodePacked(dAppDomain, sessionKeyAddress))
        );
        emit SessionKeyAdded(sessionKeyAddress, dAppDomain, sk.validUntil);
    }

    function useSessionKey(
        string memory dAppDomain,
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signature,
        uint256 nonce
    ) external payable onlyAccount returns (bytes memory result) {
        address keyAddr = domainToKey[dAppDomain];
        require(keyAddr != address(0), "No key"); // deployment-time clarity kept
        SessionKey storage sk = sessionKeys[keyAddr];
        if (!(sk.isActive && block.timestamp <= sk.validUntil))
            revert ErrorInactiveOrExpired();
        if (sk.dAppHash != keccak256(abi.encodePacked(dAppDomain)))
            revert ErrorDomainMismatch();

        bytes32 hash = keccak256(abi.encodePacked(to, value, data, nonce));
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        address recovered = ethSignedHash.recover(signature);
        if (recovered != sk.keyAddress) revert ErrorBadSignature();

        _checkLimits(sk, value, data);
        _updateUsage(sk, value);

        bool success;
        (success, result) = to.call{value: value}(data);
        if (!success) revert ErrorCallFailed();
        emit SessionKeyUsed(sk.keyAddress, dAppDomain, gasleft(), bytes4(data));
    }

    function revokeSessionKey(
        address key,
        string memory reason
    ) external onlyAccount {
        sessionKeys[key].isActive = false;
        emit SessionKeyRevoked(key, reason);
    }

    function _checkLimits(
        SessionKey storage sk,
        uint256 value,
        bytes memory data
    ) internal view {
        if (sk.allowedSelectors.length > 0) {
            bytes4 sel = bytes4(data);
            bool ok;
            for (uint i; i < sk.allowedSelectors.length; i++) {
                if (sk.allowedSelectors[i] == sel) {
                    ok = true;
                    break;
                }
            }
            if (!ok) revert ErrorFnNotAllowed();
        }
        uint256 day = block.timestamp / 1 days;
        uint256 dailyUsed = (sk.lastResetDay == day) ? sk.dailyUsed : 0;
        if (dailyUsed + value > sk.dailyLimit) revert ErrorDailyLimit();
    }

    function _updateUsage(SessionKey storage sk, uint256 value) internal {
        uint256 day = block.timestamp / 1 days;
        if (sk.lastResetDay < day) {
            sk.dailyUsed = 0;
            sk.lastResetDay = day;
        }
        sk.dailyUsed += value;
        sk.totalUsed += value;
    }
}
