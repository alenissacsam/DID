// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IVerificationLogger.sol";

contract SystemToken is ERC20, ERC20Burnable, ERC20Pausable, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    struct VestingSchedule {
        uint256 totalAmount;
        uint256 startTime;
        uint256 cliffDuration;
        uint256 duration;
        uint256 slicePeriodSeconds;
        bool revocable;
        uint256 amountWithdrawn;
        bool revoked;
    }

    mapping(address => VestingSchedule[]) private vestingSchedules;
    mapping(address => bool) public blacklisted;

    IVerificationLogger public verificationLogger;

    uint256 public constant INITIAL_SUPPLY = 1000000000 * 10 ** 18; // 1B tokens
    uint256 public constant MAX_SUPPLY = 10000000000 * 10 ** 18; // 10B tokens max

    // Allocation percentages (basis points - 10000 = 100%)
    uint256 public constant COMMUNITY_ALLOCATION = 4000; // 40%
    uint256 public constant TEAM_ALLOCATION = 2000; // 20%
    uint256 public constant TREASURY_ALLOCATION = 1500; // 15%
    uint256 public constant ECOSYSTEM_ALLOCATION = 1500; // 15%
    uint256 public constant PUBLIC_SALE_ALLOCATION = 1000; // 10%

    address public communityWallet;
    address public teamWallet;
    address public treasuryWallet;
    address public ecosystemWallet;

    event VestingCreated(
        address indexed beneficiary,
        uint256 amount,
        uint256 duration
    );
    event TokensWithdrawn(address indexed beneficiary, uint256 amount);
    event VestingRevoked(address indexed beneficiary, uint256 scheduleIndex);
    event Blacklisted(address indexed account);
    event Unblacklisted(address indexed account);

    constructor(
        address _communityWallet,
        address _teamWallet,
        address _treasuryWallet,
        address _ecosystemWallet,
        address _verificationLogger
    ) ERC20("EduCert Token", "EDU") {
        require(_communityWallet != address(0), "Invalid community wallet");
        require(_teamWallet != address(0), "Invalid team wallet");
        require(_treasuryWallet != address(0), "Invalid treasury wallet");
        require(_ecosystemWallet != address(0), "Invalid ecosystem wallet");
        require(_verificationLogger != address(0), "Invalid logger address");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(BURNER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        communityWallet = _communityWallet;
        teamWallet = _teamWallet;
        treasuryWallet = _treasuryWallet;
        ecosystemWallet = _ecosystemWallet;
        verificationLogger = IVerificationLogger(_verificationLogger);

        // Mint initial supply
        _mint(address(this), INITIAL_SUPPLY);

        // Distribute initial allocations
        _distributeInitialTokens();
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        require(!blacklisted[to], "Address blacklisted");

        _mint(to, amount);

        verificationLogger.logEvent(
            "TOKENS_MINTED",
            to,
            keccak256(abi.encodePacked(amount))
        );
    }

    function burn(uint256 amount) public override {
        super.burn(amount);

        verificationLogger.logEvent(
            "TOKENS_BURNED",
            msg.sender,
            keccak256(abi.encodePacked(amount))
        );
    }

    function burnFrom(
        address account,
        uint256 amount
    ) public override onlyRole(BURNER_ROLE) {
        super.burnFrom(account, amount);

        verificationLogger.logEvent(
            "TOKENS_BURNED_FROM",
            account,
            keccak256(abi.encodePacked(amount, msg.sender))
        );
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function blacklist(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(account != address(0), "Cannot blacklist zero address");
        blacklisted[account] = true;

        verificationLogger.logEvent("ADDRESS_BLACKLISTED", account, bytes32(0));

        emit Blacklisted(account);
    }

    function unblacklist(
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        blacklisted[account] = false;

        verificationLogger.logEvent(
            "ADDRESS_UNBLACKLISTED",
            account,
            bytes32(0)
        );

        emit Unblacklisted(account);
    }

    function createVestingSchedule(
        address beneficiary,
        uint256 amount,
        uint256 startTime,
        uint256 cliffDuration,
        uint256 duration,
        uint256 slicePeriodSeconds,
        bool revocable
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(beneficiary != address(0), "Invalid beneficiary");
        require(amount > 0, "Amount must be positive");
        require(duration >= cliffDuration, "Duration < cliff");
        require(
            balanceOf(address(this)) >= amount,
            "Insufficient contract balance"
        );

        vestingSchedules[beneficiary].push(
            VestingSchedule({
                totalAmount: amount,
                startTime: startTime,
                cliffDuration: cliffDuration,
                duration: duration,
                slicePeriodSeconds: slicePeriodSeconds,
                revocable: revocable,
                amountWithdrawn: 0,
                revoked: false
            })
        );

        verificationLogger.logEvent(
            "VESTING_CREATED",
            beneficiary,
            keccak256(abi.encodePacked(amount, duration))
        );

        emit VestingCreated(beneficiary, amount, duration);
    }

    function withdraw(uint256 scheduleIndex) external {
        require(
            scheduleIndex < vestingSchedules[msg.sender].length,
            "Invalid schedule index"
        );

        VestingSchedule storage schedule = vestingSchedules[msg.sender][
            scheduleIndex
        ];
        require(!schedule.revoked, "Schedule revoked");

        uint256 withdrawable = _computeReleasableAmount(schedule);
        require(withdrawable > 0, "No tokens to withdraw");

        schedule.amountWithdrawn += withdrawable;
        _transfer(address(this), msg.sender, withdrawable);

        verificationLogger.logEvent(
            "VESTED_TOKENS_WITHDRAWN",
            msg.sender,
            keccak256(abi.encodePacked(withdrawable, scheduleIndex))
        );

        emit TokensWithdrawn(msg.sender, withdrawable);
    }

    function revokeVesting(
        address beneficiary,
        uint256 scheduleIndex
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            scheduleIndex < vestingSchedules[beneficiary].length,
            "Invalid schedule index"
        );

        VestingSchedule storage schedule = vestingSchedules[beneficiary][
            scheduleIndex
        ];
        require(schedule.revocable, "Schedule not revocable");
        require(!schedule.revoked, "Already revoked");

        uint256 withdrawable = _computeReleasableAmount(schedule);
        if (withdrawable > 0) {
            schedule.amountWithdrawn += withdrawable;
            _transfer(address(this), beneficiary, withdrawable);
        }

        schedule.revoked = true;

        verificationLogger.logEvent(
            "VESTING_REVOKED",
            beneficiary,
            keccak256(abi.encodePacked(scheduleIndex))
        );

        emit VestingRevoked(beneficiary, scheduleIndex);
    }

    function getVestingSchedule(
        address beneficiary,
        uint256 index
    )
        external
        view
        returns (
            uint256 totalAmount,
            uint256 startTime,
            uint256 cliffDuration,
            uint256 duration,
            uint256 amountWithdrawn,
            bool revoked,
            uint256 withdrawable
        )
    {
        require(index < vestingSchedules[beneficiary].length, "Invalid index");

        VestingSchedule memory schedule = vestingSchedules[beneficiary][index];
        uint256 releasable = _computeReleasableAmount(schedule);

        return (
            schedule.totalAmount,
            schedule.startTime,
            schedule.cliffDuration,
            schedule.duration,
            schedule.amountWithdrawn,
            schedule.revoked,
            releasable
        );
    }

    function getVestingScheduleCount(
        address beneficiary
    ) external view returns (uint256) {
        return vestingSchedules[beneficiary].length;
    }

    function getTotalVestedAmount(
        address beneficiary
    ) external view returns (uint256) {
        uint256 totalVested = 0;
        for (uint256 i = 0; i < vestingSchedules[beneficiary].length; i++) {
            if (!vestingSchedules[beneficiary][i].revoked) {
                totalVested += vestingSchedules[beneficiary][i].totalAmount;
            }
        }
        return totalVested;
    }

    function _computeReleasableAmount(
        VestingSchedule memory schedule
    ) private view returns (uint256) {
        if (schedule.revoked) return 0;
        if (block.timestamp < schedule.startTime + schedule.cliffDuration) {
            return 0;
        }

        uint256 timeFromStart = block.timestamp - schedule.startTime;
        uint256 vestedAmount;

        if (timeFromStart >= schedule.duration) {
            vestedAmount = schedule.totalAmount;
        } else {
            // Ensure slicePeriodSeconds is not zero to prevent division by zero
            require(schedule.slicePeriodSeconds > 0, "Invalid slice period");
            require(schedule.duration > 0, "Invalid duration");

            uint256 vestedPeriods = timeFromStart / schedule.slicePeriodSeconds;
            vestedAmount =
                (schedule.totalAmount *
                    vestedPeriods *
                    schedule.slicePeriodSeconds) /
                schedule.duration;
        }

        // Ensure we don't return more than what's available
        if (vestedAmount > schedule.totalAmount) {
            vestedAmount = schedule.totalAmount;
        }

        if (vestedAmount <= schedule.amountWithdrawn) {
            return 0;
        }

        return vestedAmount - schedule.amountWithdrawn;
    }

    function _distributeInitialTokens() private {
        uint256 communityAmount = (INITIAL_SUPPLY * COMMUNITY_ALLOCATION) /
            10000;
        uint256 teamAmount = (INITIAL_SUPPLY * TEAM_ALLOCATION) / 10000;
        uint256 treasuryAmount = (INITIAL_SUPPLY * TREASURY_ALLOCATION) / 10000;
        uint256 ecosystemAmount = (INITIAL_SUPPLY * ECOSYSTEM_ALLOCATION) /
            10000;
        uint256 publicSaleAmount = (INITIAL_SUPPLY * PUBLIC_SALE_ALLOCATION) /
            10000;

        // Community allocation - immediate transfer
        _transfer(address(this), communityWallet, communityAmount);

        // Team allocation - 2 year vesting with 6 month cliff
        createVestingSchedule(
            teamWallet,
            teamAmount,
            block.timestamp,
            180 days, // 6 month cliff
            730 days, // 2 years
            30 days, // Monthly releases
            true // Revocable
        );

        // Treasury allocation - immediate transfer
        _transfer(address(this), treasuryWallet, treasuryAmount);

        // Ecosystem allocation - immediate transfer
        _transfer(address(this), ecosystemWallet, ecosystemAmount);

        // Public sale - keep in contract for distribution
        // The remaining tokens stay in contract for public sale
    }

    function _update(
        address from,
        address to,
        uint256 amount
    ) internal override(ERC20, ERC20Pausable) {
        require(!blacklisted[from] && !blacklisted[to], "Blacklisted address");
        super._update(from, to, amount);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
