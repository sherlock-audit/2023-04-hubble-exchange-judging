lil.eth

high

# Oracle.sol Assume that stablecoin Price is stable

## Summary

When calculating price either via `oracle.sol#getUnderlyingPrice()` or `oracle.sol#getUnderlyingTwapPrice()` a check is made whether underlying token for which we are gathering price is a stablecoin or not , if yes a stable value is returned, which is wrong

## Vulnerability Detail

Check made on `oracle.sol`:
```solidity
        //E if token is a stablecoin we return it's price 
        if (stablePrice[underlying] != 0) {
            return stablePrice[underlying];
        }
```
but in DEFI we can't assume a price is stable , regarding UST debacle and USDT or USDC depeg there is always a risk that price won't be the same as it has been fixed in `Oracle.sol#setStablePrice(underlying,price)` : 
```solidity
    //E set stablePrice for a stableCoin
    function setStablePrice(address underlying, int256 price) external onlyGovernance {
        requireNonEmptyAddress(underlying);
        require(price > 0, "stablePrice=0");
        stablePrice[underlying] = price;
    }
```
So using this kind of function is really a bad way of gathering stablecoin price and could lead to liquidation , loss of funds ,bots opportunity when a depeg happen for users using stablecoin prices in all the hubble protocol

## Impact

Liquidation,manipulation,loss of funds for users that are using hubble protocol trusting stablecoin price to be always stable

## Code Snippet

https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L44-L46

## Tool used

Manual Review

## Recommendation
Consider using a price feed by trusted and established oracle providers like Chainlink, Band Protocol or Flux to gather stablecoins prices