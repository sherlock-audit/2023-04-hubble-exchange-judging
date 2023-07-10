rogue-lion-0619

high

# Withdrawal period can be bypassed in InsuranceFund.sol

## Summary

The report uncovers a vulnerability in the InsuranceFund.sol contract that allows users to bypass the withdrawal timelock. The vulnerability is described in detail, highlighting the specific code snippets involved. The impact of this vulnerability is explained, and a recommendation is provided to address the issue.

## Vulnerability Detail

The vulnerability lies in the withdrawal process implemented in the `unbondShares` function of the InsuranceFund.sol contract. When initiating the withdrawal process, users can transfer their shares to another account or use flash loans to acquire a large amount of shares. They can then unbond their shares and transfer them elsewhere after the withdrawal period expires. By doing so, users can bypass the withdrawal timelock and freely withdraw their shares whenever they want, regardless of the original withdrawal period.

The issue is caused by the verification check in the `_beforeTokenTransfer` internal function. The code snippet below demonstrates this:

```solidity
function _beforeTokenTransfer(address from, address to, uint256 amount) override internal view {
    if (from == address(0) || to == address(0)) return; // gas optimization for _mint and _burn
    if (!_hasWithdrawPeriodElapsed(_blockTimestamp(), unbond[from].unbondTime)) {
        require(amount <= balanceOf(from) - unbond[from].shares, "shares_are_unbonding");
    }
}
```

The vulnerability arises from using the spot share balance to check if shares are unbonding, which can be manipulated by transferring shares to other accounts. Consequently, users only need to wait for the first withdrawal period instead of the full withdrawal time period, allowing them to bypass the withdrawal timelock and withdraw shares at their convenience.

A similar finding has been reported in a previous audit issue: [link to similar finding](https://github.com/sherlock-audit/2023-02-carapace-judging/issues/292).

## Impact

The impact of this vulnerability is that users can bypass the withdrawal timelock implemented in the InsuranceFund.sol contract. This allows them to freely transfer and unbond their shares before the withdrawal period expires, enabling withdrawals at any time they desire. The intended timelock mechanism is effectively circumvented.

## Code Snippet

The vulnerable code snippet can be found at the following location:

- [InsuranceFund.sol - Line 118](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/InsuranceFund.sol#L118)

- [here](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/1f9a5ed0ca8f6004bbb7b099ecbb8ae796557849/hubble-protocol/contracts/InsuranceFund.sol#L277)

## Tool Used

Manual Review

## Recommendation

To address the vulnerability, it is recommended to modify the implementation of the withdrawal process in the InsuranceFund.sol contract. One possible solution is to lock users' shares during the withdrawal timelock period, preventing them from transferring shares to other accounts or using flash loans to manipulate the unbonding process. By disallowing spot balance checks and utilizing more secure mechanisms for verifying the withdrawal timelock, the vulnerability can be mitigated.

Implementing these changes will ensure that the withdrawal timelock functions as intended, preventing users from bypassing the timelock period and withdrawing shares at their convenience.