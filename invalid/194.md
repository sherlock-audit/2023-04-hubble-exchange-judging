lil.eth

medium

# Small depositors might receive zero shares due to integer division in depositFor function

## Summary
Users who deposit a small amount of tokens using the `InsuranceFund.sol#depositFor()` function could receive zero shares, even if the total pool value is non-zero , it would be better to revert with an error message if the amount of shares is 0

## Vulnerability Detail

In the `InsuranceFund.sol#depositFor` function, the number of shares a depositor receives is calculated as follows:
```solidity
shares = amount * _totalSupply / _pool;
```
Where : 

- `amount` = amount to be deposited for `msg.sender``
- `_totalSupply` = number of InsuranceFund shares already minted
- `_pool`= for all supported assets, _pool = number of tokens deposited in the `insuranceFund.sol` contract multiply price of token



## Impact

## Code Snippet

## Tool used

Manual Review

## Recommendation


## Summary
Users who deposit a small amount of tokens using the `InsuranceFund.sol#depositFor()` function could receive zero shares, even if the total pool value is non-zero , it would be better to revert with an error message if the amount of shares is 0

## Vulnerability Detail

In the `InsuranceFund.sol#depositFor` function, the number of shares a depositor receives is calculated as follows:
```solidity
shares = amount * _totalSupply / _pool;
```
Where : 

- `amount` = amount to be deposited for `msg.sender``
- `_totalSupply` = number of InsuranceFund shares already minted
- `_pool`= for all supported assets, _pool = number of tokens deposited in the `insuranceFund.sol` contract multiply price of token

so while `amount * _totalSupply < _pool` , amount of shares to be minted will be equal to 0, making money deposited by depositor lost.
Regarding how `_pool` value is constructed , all this calculations is vulnerable for sandwich attacks. 

Here's an illustration: assume that amount = 9, _totalSupply = 1000, and _pool = 100000. Then the resulting shares will be (1*1000)/100000 = 0.


** same for the withdraw process where an amount refunded depends on `totalSupply()` then could be influenced by a big depositor just before, using a sandwich attack : 
```solidity
amount = balance() * shares / totalSupply();
```

## Impact

Users who make small deposits might receive zero shares and they will lose money, the function should revert for 0 shares amount.

## Code Snippet
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol#L107

https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol#L215

## Tool used

Manual Review

## Recommendation

Implement either kind of scaling factor : 
```solidity
uint constant SCALING_FACTOR = 1e18;
shares = amount * _totalSupply * SCALING_FACTOR / _pool;
shares = shares / SCALING_FACTOR;
```

Or add others parameter to the `insuranceFund.sol#deposit()`function like minSharesReceived to add a "slippage" defense for users. who deposit