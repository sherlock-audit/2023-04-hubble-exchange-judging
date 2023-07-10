0x52

medium

# Malicious user can grief withdrawing users via VUSD reentrancy

## Summary

VUSD#processWithdraw makes a call to withdrawal.usr to send the withdrawn gas token. processWithdrawals is the only nonreentrant function allowing a user to create a smart contract that uses it's receive function to deposit then immediately withdraw to indefinitely lengthen the withdrawal queue and waste large amounts of caller gas.

## Vulnerability Detail

[VUSD.sol#L69-L77](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/VUSD.sol#L69-L77)

        while (i < withdrawals.length && (i - start) < maxWithdrawalProcesses) {
            Withdrawal memory withdrawal = withdrawals[i];
            if (reserve < withdrawal.amount) {
                break;
            }

            (bool success, bytes memory data) = withdrawal.usr.call{value: withdrawal.amount}("");
            if (success) {
                reserve -= withdrawal.amount;

To send the withdrawn gas token to the user VUSD#processWithdrawals utilizes a call with no data. When received by a contract this will trigger it's receive function. This can be abused to continually grief users who withdraw with no recurring cost to the attacker. To exploit this the attacker would withdraw VUSD to a malicious contract. This contract would deposit the received gas token then immediately withdraw it. This would lengthen the queue. Since the queue is first-in first-out a user would be forced to process all the malicious withdrawals before being able to process their own. While processing them they would inevitably reset the grief for the next user.

NOTE: I am submitting this as a separate issue apart from my other two similar issues. I believe it should be a separate issue because even though the outcome is similar the root cause is entirely different. Those are directly related to the incorrect call parameters while the root cause of this issue is that both mintWithReserve and withdraw/withdrawTo lack the reentrant modifier allowing this malicious reentrancy.

## Impact

Malicious user can maliciously reenter VUSD to grief users via unnecessary gas wastage 

## Code Snippet

[VUSD.sol#L45-L48](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/VUSD.sol#L45-L48)

[VUSD.sol#L50-L52](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/VUSD.sol#L50-L52)

[VUSD.sol#L58-L60](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/VUSD.sol#L58-L60)

## Tool used

Manual Review

## Recommendation

Add the nonreentrant modifer to mintWithReserve withdraw and withdrawTo