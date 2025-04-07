// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {LibSort} from "solady/utils/LibSort.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {LibBit} from "solady/utils/LibBit.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {FixedPointMathLib as Math} from "solady/utils/FixedPointMathLib.sol";
import {DateTimeLib} from "solady/utils/DateTimeLib.sol";
import {DynamicArrayLib} from "solady/utils/DynamicArrayLib.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IExecutionHook} from "../../interfaces/IExecutionHook.sol";
import {AccountKeyHash, AccountKeyHashLib} from "../shared/AccountKeyHashLib.sol";

enum SpendPeriod {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year
}

interface ISpendingLimitHook is IExecutionHook {
    /// @dev Exceeded the spend limit.
    error ExceededSpendLimit();

    /// @dev Emitted when a spend limit is set.
    event SpendLimitSet(AccountKeyHash accountKeyHash, address token, SpendPeriod period, uint256 limit);

    /// @dev Emitted when a spend limit is removed.
    event SpendLimitRemoved(AccountKeyHash accountKeyHash, address token, SpendPeriod period);

    function setSpendLimit(bytes32 keyHash, address token, SpendPeriod period, uint256 limit) external;
}

/// @title SpendingLimitHook
/// @author modified from https://github.com/ithacaxyz/account/blob/main/src/GuardedExecutor.sol
contract SpendingLimitHook is ISpendingLimitHook {
    using EnumerableSetLib for *;
    using DynamicArrayLib for *;
    using AccountKeyHashLib for bytes32;

    ////////////////////////////////////////////////////////////////////////
    // Structs
    ////////////////////////////////////////////////////////////////////////

    /// @dev Information about a spend.
    /// All timestamp related values are Unix timestamps in seconds.
    struct SpendInfo {
        /// @dev Address of the token. `address(0)` denotes native token.
        address token;
        /// @dev The type of period.
        SpendPeriod period;
        /// @dev The maximum spend limit for the period.
        uint256 limit;
        /// @dev The amount spent in the last updated period.
        uint256 spent;
        /// @dev The start of the last updated period.
        uint256 lastUpdated;
        /// @dev The amount spent in the current period.
        uint256 currentSpent;
        /// @dev The start of the current period.
        uint256 current;
    }

    /// @dev Holds the storage for the token period spend limits.
    /// All timestamp related values are Unix timestamps in seconds.
    struct TokenPeriodSpendStorage {
        /// @dev The maximum spend limit for the period.
        uint256 limit;
        /// @dev The amount spent in the last updated period.
        uint256 spent;
        /// @dev The start of the last updated period (unix timestamp).
        uint256 lastUpdated;
    }

    /// @dev Holds the storage for the token spend limits.
    struct TokenSpendStorage {
        /// @dev An enumerable set of the periods.
        EnumerableSetLib.Uint8Set periods;
        /// @dev Mapping of `uint8(period)` to `TokenPeriodSpendStorage`.
        mapping(uint256 => TokenPeriodSpendStorage) spends;
    }

    /// @dev Holds the storage for spend permissions and the current spend state.
    struct SpendStorage {
        /// @dev An enumerable set of the tokens.
        EnumerableSetLib.AddressSet tokens;
        /// @dev Mapping of `token` to `TokenSpendStorage`.
        mapping(address => TokenSpendStorage) spends;
    }

    mapping(AccountKeyHash => SpendStorage) public spendStorage;

    struct TempStorage {
        uint256 totalNativeSpend;
        address[] erc20s;
        uint256[] transferAmounts;
        uint256[] balancesBefore;
    }

    /// @dev Set the spend limit for a key hash.
    /// Uses msg.sender to compute the accountKeyHash.
    function setSpendLimit(bytes32 keyHash, address token, SpendPeriod period, uint256 limit) external {
        AccountKeyHash accountKeyHash = keyHash.wrap(msg.sender);
        SpendStorage storage spends = spendStorage[accountKeyHash];
        spends.tokens.add(token, 64); // Max capacity of 64.

        TokenSpendStorage storage tokenSpends = spends.spends[token];
        tokenSpends.periods.add(uint8(period));

        tokenSpends.spends[uint8(period)].limit = limit;
        emit SpendLimitSet(accountKeyHash, token, period, limit);
    }

    function beforeExecute(bytes32 keyHash, address to, uint256 value, bytes calldata data) external returns (bytes4, bytes memory beforeExecuteData) {
        DynamicArrayLib.DynamicArray memory erc20s;
        DynamicArrayLib.DynamicArray memory transferAmounts;

        SpendStorage storage spends = spendStorage[keyHash.wrap(msg.sender)];
        TempStorage memory tempStorage;
        // Collect all ERC20 tokens that need to be guarded,
        // and initialize their transfer amounts as zero.
        // Used for the check on their before and after balances, in case the batch calls
        // some contract that is authorized to transfer out tokens on behalf of the eoa.
        uint256 n = spends.tokens.length();
        for (uint256 i; i < n; ++i) {
            address token = spends.tokens.at(i);
            if (token != address(0)) {
                erc20s.p(token);
                transferAmounts.p(uint256(0));
            }
        }

        uint256 totalNativeSpend;
        if (value != 0) totalNativeSpend += value;

        uint256[] memory balancesBefore = DynamicArrayLib.malloc(erc20s.length());

        if (data.length < 4) {
            return (IExecutionHook.beforeExecute.selector, abi.encode(tempStorage));
        }

        // We will only filter based on functions that are known to use `msg.sender`.
        // For signature-based approvals (e.g. permit), we can't do anything
        // to guard, as anyone else can directly submit the calldata and the signature.
        uint32 fnSel = uint32(bytes4(LibBytes.loadCalldata(data, 0x00)));
        // `transfer(address,uint256)`.
        if (fnSel == 0xa9059cbb) {
            erc20s.p(to);
            transferAmounts.p(LibBytes.loadCalldata(data, 0x24)); // `amount`.
        }

        // Sum transfer amounts, grouped by the ERC20s. In-place.
        LibSort.groupSum(erc20s.data, transferAmounts.data);

        // Collect the ERC20 balances before the batch execution.
        for (uint256 i; i < erc20s.length(); ++i) {
            address token = erc20s.getAddress(i);
            balancesBefore.set(i, SafeTransferLib.balanceOf(token, msg.sender));
        }

        tempStorage = TempStorage({
            totalNativeSpend: totalNativeSpend,
            erc20s: erc20s.asAddressArray(),
            transferAmounts: transferAmounts.asUint256Array(),
            balancesBefore: balancesBefore
        });

        return (IExecutionHook.beforeExecute.selector, abi.encode(tempStorage));
    }

    function afterExecute(bytes32 keyHash, bytes memory beforeExecuteData) external returns (bytes4) {
        // Ensure spends in beforeExecuteData are within limits, revert if not.
        TempStorage memory tempStorage = abi.decode(beforeExecuteData, (TempStorage));
        SpendStorage storage spends = spendStorage[keyHash.wrap(msg.sender)];

        // Ensure spends in beforeExecuteData are within limits, revert if not.
        // Perform after the `_execute`, so that in the case where `calls`
        // contain a `setSpendLimit`, it will affect the `_incrementSpent`.
        
        // `_incrementSpent` is an no-op if the token does not have an active spend limit.
        _incrementSpent(spends.spends[address(0)], tempStorage.totalNativeSpend);

        // Increments the spent amounts.
        for (uint256 i; i < tempStorage.erc20s.length; ++i) {
            address token = tempStorage.erc20s[i];
            TokenSpendStorage storage tokenSpends = spends.spends[token];
            if (tokenSpends.periods.length() == uint256(0)) continue;
            _incrementSpent(
                tokenSpends,
                // While we can actually just use the difference before and after,
                // we also want to let the sum of the transfer amounts in the calldata to be capped.
                // This prevents tokens to be used as flash loans, and also handles cases
                // where the actual token transfers might not match the calldata amounts.
                // There is no strict definition on what constitutes spending,
                // and we want to be as conservative as possible.
                Math.max(
                    tempStorage.transferAmounts[i],
                    Math.saturatingSub(
                        tempStorage.balancesBefore[i], SafeTransferLib.balanceOf(token, msg.sender)
                    )
                )
            );
        }

        return IExecutionHook.afterExecute.selector;
    }

    /// @dev Rounds the unix timestamp down to the period.
    function startOfSpendPeriod(uint256 unixTimestamp, SpendPeriod period)
        public
        pure
        returns (uint256)
    {
        if (period == SpendPeriod.Minute) return Math.rawMul(Math.rawDiv(unixTimestamp, 60), 60);
        if (period == SpendPeriod.Hour) return Math.rawMul(Math.rawDiv(unixTimestamp, 3600), 3600);
        if (period == SpendPeriod.Day) return Math.rawMul(Math.rawDiv(unixTimestamp, 86400), 86400);
        if (period == SpendPeriod.Week) return DateTimeLib.mondayTimestamp(unixTimestamp);
        (uint256 year, uint256 month,) = DateTimeLib.timestampToDate(unixTimestamp);
        // Note: DateTimeLib's months and month-days start from 1.
        if (period == SpendPeriod.Month) return DateTimeLib.dateToTimestamp(year, month, 1);
        if (period == SpendPeriod.Year) return DateTimeLib.dateToTimestamp(year, 1, 1);
        revert(); // We shouldn't hit here.
    }

    /// @notice Increments the amount spent.
    /// @dev reverts if the amount spent exceeds the limit.
    function _incrementSpent(TokenSpendStorage storage s, uint256 amount) internal {
        if (amount == uint256(0)) return; // Early return.
        uint8[] memory periods = s.periods.values();
        for (uint256 i; i < periods.length; ++i) {
            uint8 period = periods[i];
            TokenPeriodSpendStorage storage tokenPeriodSpend = s.spends[period];
            uint256 current = startOfSpendPeriod(block.timestamp, SpendPeriod(period));
            if (tokenPeriodSpend.lastUpdated < current) {
                tokenPeriodSpend.lastUpdated = current;
                tokenPeriodSpend.spent = 0;
            }
            if ((tokenPeriodSpend.spent += amount) > tokenPeriodSpend.limit) {
                revert ExceededSpendLimit();
            }
        }
    }
}
