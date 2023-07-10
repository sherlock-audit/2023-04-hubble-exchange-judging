rogue-lion-0619

medium

# _liquidateExactRepay has no minSeizeAmount slippage protection

## Summary

The report identifies a vulnerability in the code related to the `_liquidateExactRepay` function, which lacks slippage protection in the form of a `minSeizeAmount` parameter. The vulnerability is described, along with code snippets demonstrating the issue. The impact of this vulnerability is that the seize amount from the liquidator can be suboptimal. The report recommends allowing users to specify the `minSeizeAmount` to address this vulnerability.

## Vulnerability Detail

The vulnerability exists in the `_liquidateFlexible` function, specifically in the following code snippet:

```solidity
function _liquidateFlexible(address trader, uint maxRepay, uint idx) internal whenNotPaused returns(uint /* repayed */) {
    LiquidationBuffer memory buffer = _getLiquidationInfo(trader, idx);

    uint repay = _seizeToRepay(buffer, margin[idx][trader].toUint256());

    if (repay >= buffer.repayAble) {
        _liquidateExactRepay(
            buffer,
            trader,
            buffer.repayAble, // exact repay amount
            idx,
            0 // minSeizeAmount=0 implies accept whatever the oracle price is
        );
        return buffer.repayAble;
    }

    return _liquidateExactSeize(
        buffer,
        trader,
        maxRepay,
        idx,
        margin[idx][trader].toUint256()
    );
}
```

The vulnerability lies in the fact that the `minSeizeAmount` parameter is hardcoded to 0, which means there is no protection against slippage, and the seize amount from the liquidator can be suboptimal.

## Impact

The impact of this vulnerability is that the seize amount from the liquidator can be suboptimal due to the hardcoded `minSeizeAmount` of 0.

## Code Snippet

The vulnerable code snippets can be found at the following locations:

- [MarginAccount.sol - Line 437](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/MarginAccount.sol#L437)
- [MarginAccount.sol - Line 469](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/MarginAccount.sol#L469)

## Tool Used

Manual Review

## Recommendation

The report recommends allowing users to specify the `minSeizeAmount` parameter in the `liquidateExactRepay` function to provide slippage protection. The function signature can be updated as follows:

```solidity
function liquidateExactRepay(address trader, uint repay, uint idx, uint minSeizeAmount) external whenNotPaused {
```

This modification would allow users to define the minimum amount they are willing to seize, thus improving the protection against suboptimal seize amounts.