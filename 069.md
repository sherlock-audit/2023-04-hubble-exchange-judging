dirk_y

medium

# Setting stable price in oracle can result in arbitrate opportunities and significant bad debt if the stable depegs

## Summary
In `Oracle.sol` there is the ability for governance to manually specify the price of an underlying asset (designed for stable coins). However, when the given stable coin depegs there is now the opportunity for arbitrage and even the possibility that Hubble becomes insolvent.

## Vulnerability Detail
Firstly, it is worth noting that stable coins depeg relatively frequently. For the sake of argument let's say that a stable coin is pegged to the US Dollar and the price is set by governance to `1000000` (to 6 decimal places) in the oracle.

Probably the most important place in the protocol where the price of an asset is used is in `MarginAccount` in the `weightedAndSpotCollateral` method. This method is used under the hood to check whether a user can withdraw from the margin account and whether the user is able to be liquidated. It is also used in the AMM logic but I'll focus on the margin account case as I think that is the easiest to exploit.

Let's now say that the stable coin depegs from its $1 price. Now, a user that has already used this stable coin as collateral in the margin account should have a lower value of collateral and therefore could be at risk of being liquidated. However, because the price of the stable coin is manually pegged to $1, the unhealthy trader's position will still appear healthy. If the stable coin failed to return to it's previous $1 value then even if the price of the stable coin was changed by governance to reflect the new lower value, the amount of bad debt accrued by Hubble would be huge at the time of liquidation/settlement.

The other scenario that will be used more actively by malicious users is that they will acquire the depegged stable coin from another source at its depegged value (e.g. $0.9). The malicious user can then deposit this stable coin into the Hubble margin account at the hard coded value of $1, and open positions with a value that should ordinarily put the trader into a bad debt position.

## Impact
A short term stable coin depeg event will result in accounts not being liquidated when they should be, and it will allow users to gain from arbitrage trades where they purchase a stable coin at its depegged price and are offered a higher price in Hubble.

A permanent depeg will result in a huge amount of bad debt in Hubble and would likely cause the protocol to become insolvent due to the inability to perform liquidations during the downward price movement.

## Code Snippet
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L30-L32
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L172

## Tool used
Manual Review

## Recommendation
I would recommend not having the option to manually set and read the price of a stable coin. Yes, you protect accounts from being liquidated from a short term depeg event, however it is precisely in these volatile market periods that accounts should be able to be liquidated to prevent Hubble from accruing too much bad debt, particularly if the depeg is permanent, in which case it will likely cause Hubble to become insolvent.