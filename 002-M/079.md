lil.eth

medium

# Chainlink’s latestRoundData might return stale or incorrect results

## Summary
AMM.sol, clearingHouse.sol,InsuranceFund.sol,MarginAccount get price from `oracle.sol#getUnderlyingPrice()` which use `(,answer,,,) = AggregatorV3Interface(chainLinkAggregatorMap[underlying]).latestRoundData();` that does not check if the return value indicates stale data

## Vulnerability Detail

AMM.sol, clearingHouse.sol,InsuranceFund.sol,MarginAccount are using `latestRoundData`, but there is no check if the return value indicates stale data. 

https://docs.chain.link/docs/historical-price-data/#historical-rounds
https://docs.chain.link/docs/faq/#how-can-i-check-if-the-answer-to-a-round-is-being-carried-over-from-a-previous-round

## Impact

This could lead to stale prices according to the Chainlink documentation:

## Code Snippet

https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L33

## Tool used

Manual Review

## Recommendation
Use TwapPrice calculation or add checks for stale data 
```solidity
(uint80 roundID, int256 feedPrice, , uint256 timestamp, uint80 answeredInRound) = AggregatorV3Interface(chainLinkAggregatorMap[underlying]).latestRoundData();
require(feedPrice > 0, "Chainlink price <= 0"); 
require(answeredInRound >= roundID, "Stale price");
require(timestamp != 0, "Round not complete");
```