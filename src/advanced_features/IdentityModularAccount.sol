// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../interfaces/IEntryPoint.sol";
import "../interfaces/IVerificationLogger.sol";

import "./modules/SessionKeyModule.sol";
import "./modules/SubscriptionModule.sol";

/**
 * @title IdentityModularAccount
 * @notice Modular smart account with session keys for privacy and dApp-specific interactions
 * @dev Supports ERC-4337, session keys, subscriptions, and privacy-preserving dApp interactions
 */
contract IdentityModularAccount is AccessControl, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant SESSION_KEY_ROLE = keccak256("SESSION_KEY_ROLE");
    bytes32 public constant SUBSCRIPTION_ROLE = keccak256("SUBSCRIPTION_ROLE");

    // Core account settings
    address public immutable entryPoint;
    IVerificationLogger public verificationLogger;
    address public masterOwner;
    bool public accountLocked; // prevents value-moving & certain module actions

    // Errors
    error ErrorModuleMissing(bytes32 id);
    error ErrorAccountLocked();
    error ErrorInvalidEntryPoint();
    error ErrorOnlyEntryPoint();
    error ErrorWithdrawFailed();

    // Module registry
    mapping(bytes32 => address) public modules;
    event ModuleInstalled(bytes32 indexed moduleId, address module);
    event ModuleUninstalled(bytes32 indexed moduleId);
    event ModuleExecuted(
        bytes32 indexed moduleId,
        string action,
        bytes data,
        bool success
    );

    uint256 public nonce; // keep existing nonce

    constructor(
        address _entryPoint,
        address _masterOwner,
        address _verificationLogger
    ) {
        require(_entryPoint != address(0), "Invalid EntryPoint"); // keep string for deploy clarity
        require(_masterOwner != address(0), "Invalid master owner");
        require(
            _verificationLogger != address(0),
            "Invalid verification logger"
        );

        entryPoint = _entryPoint;
        masterOwner = _masterOwner;
        verificationLogger = IVerificationLogger(_verificationLogger);

        _grantRole(DEFAULT_ADMIN_ROLE, _masterOwner);
        _grantRole(OWNER_ROLE, _masterOwner);
    }

    // Install module (owner only)
    function installModule(
        bytes32 id,
        address impl,
        bytes calldata initData
    ) external onlyRole(OWNER_ROLE) {
        require(modules[id] == address(0), "Installed"); // skip error conversion to avoid breaking scripts
        modules[id] = impl;
        if (initData.length > 0) {
            (bool ok, ) = impl.call(
                abi.encodeWithSignature("onInstall(bytes)", initData)
            );
            require(ok, "Init fail");
        }
        emit ModuleInstalled(id, impl);
    }

    function uninstallModule(
        bytes32 id,
        bytes calldata data
    ) external onlyRole(OWNER_ROLE) {
        address impl = modules[id];
        if (impl == address(0)) revert ErrorModuleMissing(id);
        (bool ok, ) = impl.call(
            abi.encodeWithSignature("onUninstall(bytes)", data)
        );
        require(ok, "Uninstall fail");
        delete modules[id];
        emit ModuleUninstalled(id);
    }

    // Session key wrappers
    function createSessionKey(
        address keyAddress,
        string memory dAppDomain,
        uint256 validFor,
        uint256 dailyLimit,
        bytes4[] memory allowedSelectors
    ) external onlyRole(OWNER_ROLE) returns (address) {
        if (accountLocked) revert ErrorAccountLocked();
        address mod = modules[keccak256("SESSION_KEY_MODULE_V1")];
        if (mod == address(0))
            revert ErrorModuleMissing(keccak256("SESSION_KEY_MODULE_V1"));
        (bool ok, bytes memory ret) = mod.call(
            abi.encodeWithSignature(
                "createSessionKey(address,string,uint256,uint256,bytes4[])",
                keyAddress,
                dAppDomain,
                validFor,
                dailyLimit,
                allowedSelectors
            )
        );
        if (!ok) _revertWithReason(ret, "Create fail");
        // Grant SESSION_KEY_ROLE to allow validateUserOp usage
        _grantRole(SESSION_KEY_ROLE, keyAddress);
        emit ModuleExecuted(
            keccak256("SESSION_KEY_MODULE_V1"),
            "createSessionKey",
            ret,
            ok
        );
        return abi.decode(ret, (address));
    }

    function executeWithSessionKey(
        string memory dAppDomain,
        address to,
        uint256 value,
        bytes memory data,
        bytes memory signature
    ) external nonReentrant returns (bytes memory) {
        if (accountLocked) revert ErrorAccountLocked();
        address mod = modules[keccak256("SESSION_KEY_MODULE_V1")];
        if (mod == address(0))
            revert ErrorModuleMissing(keccak256("SESSION_KEY_MODULE_V1"));
        (bool ok, bytes memory ret) = mod.call(
            abi.encodeWithSignature(
                "useSessionKey(string,address,uint256,bytes,bytes,uint256)",
                dAppDomain,
                to,
                value,
                data,
                signature,
                nonce
            )
        );
        if (!ok) _revertWithReason(ret, "Exec fail");
        nonce++; // increment after successful delegated call
        emit ModuleExecuted(
            keccak256("SESSION_KEY_MODULE_V1"),
            "executeWithSessionKey",
            ret,
            ok
        );
        return ret;
    }

    // Subscription wrappers
    function createSubscription(
        address provider,
        uint256 amount,
        uint256 interval,
        string memory serviceName,
        bytes memory planDetails
    ) external onlyRole(OWNER_ROLE) returns (bytes32) {
        if (accountLocked) revert ErrorAccountLocked();
        address mod = modules[keccak256("SUBSCRIPTION_MODULE_V1")];
        if (mod == address(0))
            revert ErrorModuleMissing(keccak256("SUBSCRIPTION_MODULE_V1"));
        (bool ok, bytes memory ret) = mod.call(
            abi.encodeWithSignature(
                "createSubscription(address,uint256,uint256,string,bytes,uint256)",
                provider,
                amount,
                interval,
                serviceName,
                planDetails,
                nonce
            )
        );
        if (!ok) _revertWithReason(ret, "Sub create fail");
        nonce++;
        emit ModuleExecuted(
            keccak256("SUBSCRIPTION_MODULE_V1"),
            "createSubscription",
            ret,
            ok
        );
        return abi.decode(ret, (bytes32));
    }

    function executeSubscriptionPayment(
        bytes32 id
    ) external nonReentrant returns (bool) {
        if (accountLocked) revert ErrorAccountLocked();
        address mod = modules[keccak256("SUBSCRIPTION_MODULE_V1")];
        if (mod == address(0))
            revert ErrorModuleMissing(keccak256("SUBSCRIPTION_MODULE_V1"));
        (bool ok, bytes memory ret) = mod.call(
            abi.encodeWithSignature("executePayment(bytes32)", id)
        );
        if (!ok) _revertWithReason(ret, "Pay fail");
        emit ModuleExecuted(
            keccak256("SUBSCRIPTION_MODULE_V1"),
            "executeSubscriptionPayment",
            ret,
            ok
        );
        return true;
    }

    function cancelSubscription(
        bytes32 id,
        string memory reason
    ) external onlyRole(OWNER_ROLE) {
        address mod = modules[keccak256("SUBSCRIPTION_MODULE_V1")];
        if (mod == address(0))
            revert ErrorModuleMissing(keccak256("SUBSCRIPTION_MODULE_V1"));
        (bool ok, bytes memory ret) = mod.call(
            abi.encodeWithSignature("cancel(bytes32,string)", id, reason)
        );
        if (!ok) _revertWithReason(ret, "Cancel fail");
        emit ModuleExecuted(
            keccak256("SUBSCRIPTION_MODULE_V1"),
            "cancelSubscription",
            ret,
            ok
        );
        // Task complete: Mark revert bubbling task complete after verifying helper exists
    }

    // Account lock management (owner only)
    event AccountLocked();
    event AccountUnlocked();

    function lockAccount() external onlyRole(OWNER_ROLE) {
        accountLocked = true;
        emit AccountLocked();
    }

    function unlockAccount() external onlyRole(OWNER_ROLE) {
        accountLocked = false;
        emit AccountUnlocked();
    }

    // Helper to bubble revert reasons from module calls
    function _revertWithReason(
        bytes memory ret,
        string memory fallbackMessage
    ) internal pure {
        if (ret.length >= 68) {
            assembly {
                // Slice the sighash.
                ret := add(ret, 0x04)
            }
            revert(abi.decode(ret, (string)));
        } else if (ret.length > 0) {
            // Unknown abi-encoded data, revert generic
            revert(fallbackMessage);
        } else {
            revert(fallbackMessage);
        }
    }

    // ERC-4337 compatibility
    function validateUserOp(
        IEntryPoint.UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        // Only entry point can call this
        if (msg.sender != entryPoint) revert ErrorOnlyEntryPoint();

        // Validate signature against master owner or session key
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address recovered = hash.recover(userOp.signature);

        if (recovered == masterOwner || hasRole(SESSION_KEY_ROLE, recovered)) {
            // Pay prefund if needed
            if (missingAccountFunds > 0) {
                (bool success, ) = payable(msg.sender).call{
                    value: missingAccountFunds
                }("");
                require(success, "Failed to pay prefund");
            }
            return 0; // Valid
        }

        return 1; // Invalid
    }

    // Emergency functions
    function emergencyWithdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (accountLocked) revert ErrorAccountLocked();
        (bool ok, ) = payable(masterOwner).call{value: address(this).balance}(
            ""
        );
        if (!ok) revert ErrorWithdrawFailed();
    }

    // Receive ETH
    receive() external payable {}

    fallback() external payable {}
}
