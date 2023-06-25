0xbepresent

medium

# `Chainlink.latestRoundData()` may return stale results

## Summary

The [Oracle.getUnderlyingPrice()](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L24C14-L24C32) function is used to get the price of tokens, the problem is that [the function](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L33) does not check for stale results.

## Vulnerability Detail

The [Oracle.getUnderlyingPrice()](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L24C14-L24C32) function is used in [InsuranceFund](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol), [MarginAccount](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccount.sol) and [AMM](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/AMM.sol) contracts. The `Oracle.getUnderlyingPrice()` helps to determine the tokens prices managed in the contracts.

The problem is that there is not check for stale data. There are some [reasons](https://ethereum.stackexchange.com/questions/133242/how-future-resilient-is-a-chainlink-price-feed/133843#133843) that the price feed can become stale.

## Impact

Since the token prices are used in many contracts, stale data could be catastrophic for the project.

## Code Snippet

The [Oracle.getUnderlyingPrice()](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L24C14-L24C32) is used by the next contracts:

- [InsuranceFund](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol)
- [MarginAccount](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccount.sol)
- [AMM](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/AMM.sol)

## Tool used

Manual review

## Recommendation

Read the [updatedAt](https://docs.chain.link/data-feeds/api-reference#latestrounddata) return value from the `Chainlink.latestRoundData()` function and verify that is not older than than specific time tolerance.

```solidity
require(block.timestamp - udpatedData < toleranceTime, "stale price");
```