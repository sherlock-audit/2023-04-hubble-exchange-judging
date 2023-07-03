0x52

medium

# Failed withdrawals from VUSD#processWithdrawals will be lost forever

## Summary

When withdrawals fail inside VUSD#processWithdrawals they are permanently passed over and cannot be retried. The result is that any failed withdrawal will be lost forever.

## Vulnerability Detail

[VUSD.sol#L75-L81](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/VUSD.sol#L75-L81)

            (bool success, bytes memory data) = withdrawal.usr.call{value: withdrawal.amount}("");
            if (success) {
                reserve -= withdrawal.amount;
            } else {
                emit WithdrawalFailed(withdrawal.usr, withdrawal.amount, data);
            }
            i += 1;

If the call to withdrawal.usr fails the contract will simply emit an event and continue on with its cycle. Since there is no way to retry withdrawals, these funds will be permanently lost.

## Impact

Withdrawals that fail will be permanently locked

## Code Snippet

[VUSD.sol#L65-L85](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/VUSD.sol#L65-L85)

## Tool used

Manual Review

## Recommendation

Cache failed withdrawals and allow them to be retried or simply send VUSD to the user if it fails.