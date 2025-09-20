// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IEntryPoint
 * @notice Interface for ERC-4337 EntryPoint contract
 * @dev This is the standard interface for the EntryPoint contract in ERC-4337 Account Abstraction
 */
interface IEntryPoint {
    /**
     * @dev User operation structure as defined in ERC-4337
     */
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    /**
     * @dev Structure to hold information about a UserOperation's execution
     */
    struct UserOpInfo {
        uint256 mUserOp;
        uint256 preOpGas;
        uint256 contextOffset;
        bytes context;
    }

    /**
     * @dev Execute a batch of UserOperations
     * @param ops The array of UserOperations to execute
     * @param beneficiary The address to receive the gas fees
     */
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;

    /**
     * @dev Execute a single UserOperation
     * @param callData The call data to execute
     * @param opInfo Additional information about the operation
     * @param context The context from validation phase
     */
    function innerHandleOp(bytes calldata callData, UserOpInfo memory opInfo, bytes calldata context)
        external
        returns (uint256 actualGasCost);

    /**
     * @dev Get the nonce for a sender
     * @param sender The address to get nonce for
     * @param key The nonce key (for multiple nonce spaces)
     * @return The current nonce
     */
    function getNonce(address sender, uint192 key) external view returns (uint256);

    /**
     * @dev Get the hash of a UserOperation
     * @param userOp The UserOperation to hash
     * @return The hash of the UserOperation
     */
    function getUserOpHash(UserOperation calldata userOp) external view returns (bytes32);

    /**
     * @dev Deposit ETH for gas fees
     */
    function depositTo(address account) external payable;

    /**
     * @dev Withdraw deposited ETH
     * @param withdrawAddress The address to withdraw to
     * @param withdrawAmount The amount to withdraw
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;

    /**
     * @dev Get the balance of deposits for an account
     * @param account The account to check
     * @return The deposit balance
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Get the deposit info for an account
     * @param account The account to check
     * @return deposit The deposit amount
     * @return staked Whether the account is staked
     * @return stake The stake amount
     * @return unstakeDelaySec The unstake delay in seconds
     * @return withdrawTime The withdrawal time
     */
    function getDepositInfo(address account)
        external
        view
        returns (uint256 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime);

    /**
     * @dev Add stake for the sender
     * @param unstakeDelaySec The delay before unstaking is allowed
     */
    function addStake(uint32 unstakeDelaySec) external payable;

    /**
     * @dev Unlock the stake (start unstaking process)
     */
    function unlockStake() external;

    /**
     * @dev Withdraw the stake after the delay period
     * @param withdrawAddress The address to withdraw to
     */
    function withdrawStake(address payable withdrawAddress) external;

    /**
     * @dev Emitted when a UserOperation is executed
     * @param userOpHash The hash of the executed UserOperation
     * @param sender The sender of the UserOperation
     * @param paymaster The paymaster used (if any)
     * @param nonce The nonce of the operation
     * @param success Whether the operation succeeded
     * @param actualGasCost The actual gas cost of the operation
     * @param actualGasUsed The actual gas used
     */
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    /**
     * @dev Emitted when an account is deployed
     * @param userOpHash The hash of the UserOperation that deployed the account
     * @param sender The deployed account address
     * @param factory The factory that deployed the account
     * @param paymaster The paymaster used (if any)
     */
    event AccountDeployed(bytes32 indexed userOpHash, address indexed sender, address factory, address paymaster);

    /**
     * @dev Emitted when a UserOperation reverts
     * @param userOpHash The hash of the reverted UserOperation
     * @param sender The sender of the UserOperation
     * @param nonce The nonce of the operation
     * @param revertReason The reason for the revert
     */
    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );
}
