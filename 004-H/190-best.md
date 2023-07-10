rogue-lion-0619

high

# Malicious user can removeMargin more than one times

## Summary

The report reveals a vulnerability in the code that allows malicious users to remove margin more than once, leading to the theft of funds from the MarginAccount.sol contract. The vulnerability is explained in detail along with code snippets demonstrating the issue. The impact of this vulnerability is that malicious users can drain the funds from the MarginAccount.sol contract. The report provides a recommendation to address the vulnerability.

## Vulnerability Detail

The vulnerability exists in the MarginAccount.sol contract. The code snippet below shows the `addMarginFor` function, which allows users to add margin:

```solidity
function addMarginFor(uint idx, uint amount, address to) override public whenNotPaused {
    require(amount > 0, "Add non-zero margin");
    if (idx == VUSD_IDX) {
        _transferInVusd(_msgSender(), amount);
    } else {
        supportedCollateral[idx].token.safeTransferFrom(_msgSender(), address(this), amount);
    }
    margin[idx][to] += amount.toInt256();
    emit MarginAdded(to, idx, amount, _blockTimestamp());
}
```

The margin balance is tracked using `margin[idx][to] += amount.toInt256();`. However, the issue arises when removing the margin account with the `_removeMarginFor` function:

```solidity
function _removeMarginFor(uint idx, uint amount, address trader, address receiver) internal {
    _validateRemoveMargin(idx, amount, trader);
    if (idx == VUSD_IDX) {
        _transferOutVusd(receiver, amount);
    } else {
        supportedCollateral[idx].token.safeTransfer(receiver, amount);
    }
    emit MarginRemoved(trader, idx, amount, _blockTimestamp());
}
```

The `margin[idx][to]` value is not updated to decrease the balance, allowing users to repeatedly remove margin and drain the funds from the MarginAccount.sol contract.

## Impact

The impact of this vulnerability is that malicious users can remove margin more than once, leading to the theft of funds from the MarginAccount.sol contract.

## Code Snippet

The vulnerable code snippets can be found at the following locations:

- [MarginAccount.sol - Line 154](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/MarginAccount.sol#L154)
- [MarginAccount.sol - Line 604](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/MarginAccount.sol#L604)

## Tool Used

Manual Review

## Recommendation

The report recommends updating the `margin[idx][to]` value when removing margin to ensure the balance is correctly decreased. Additionally, it suggests implementing proper reentrancy protection to prevent potential attacks.