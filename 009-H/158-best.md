0x52

high

# Malicious user can permanently break VUSD#processWithdrawals by returning huge amounts of data

## Summary

VUSD#processWithdraw makes a call to withdrawal.usr to send the withdrawn gas token. It then stores the return data of the call in memory. A malicious user could set the withdrawal target to a malicious contract that would return an extremely large data amount that would guaranteed cause an OOG error when loaded to memory. The result is that all withdrawals would be permanently locked causing massive loss to all VUSD holders.

NOTE: I am submitting this as a separate issue apart from my other two similar issues. I believe it should be a separate issue because even though the outcome is similar the root cause is different. The vulnerability exploited in this issue is that the return data is stored and that there is no cap on it's size. Capping the gas usage of the call won't fix this.

## Vulnerability Detail

See summary.

## Impact

All withdrawals can be permanently broken

## Code Snippet

[VUSD.sol#L65-L85](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/VUSD.sol#L65-L85)

## Tool used

Manual Review

## Recommendation

Cap the data returned or don't store the return data at all