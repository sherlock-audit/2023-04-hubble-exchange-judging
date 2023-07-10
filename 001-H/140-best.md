0xDjango

high

# First depositor can break minting of shares

## Summary
The common "first depositor" vulnerability is found in `InsuranceFund.depositFor()`. The first account to deposit into the insurance fund can steal value from subsequent depositors by:

- Minting `1 wei` shares
- Directly transferring assets into the contract to inflate the `poolValue`
- Subsequent depositors deposit assets but are minted `0 shares` due to precision loss
- First depositor steals the assets

## Vulnerability Detail
The depositor's shares are calculated via:

```solidity
        if (_pool == 0) {
            shares = amount;
        } else {
            shares = amount * _totalSupply / _pool;
        }
```

Upon first deposit, the `_pool` value will be 0. The attacker will transact with an `amount` = `1 wei` to mint 1 wei of shares. Then the attacker will transfer some value of asset directly to the contract. For this example, the attacker transfers 10,000 USDC.

Next, a subsequent depositor attempts to mint shares with 5,000 VUSD.

`shares = 5000 ether * 1 wei / 10,000 ether = 0` due to precision loss.

The attacker can now withdraw the second depositor's assets.

## Impact
- Theft of deposits

## Code Snippet
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol#L104-L108

## Tool used
Manual Review

## Recommendation
Mint a certain number of shares and transfer them to address(0) within the `initialize()` function.
