dirk_y

medium

# Malicious validators can decline to call settleFunding to prevent funding payments from taking place

## Summary
A set of malicious validators can decline to call `settleFunding` and therefore prevent all funding payments for positions from taking place without affecting the apparent health of the protocol to unknowing outside observers.

## Vulnerability Detail
The `settleFunding` method in `OrderBook.sol` can only be called by validators:

```solidity
function settleFunding() external whenNotPaused onlyValidator {
        clearingHouse.settleFunding();
    }
```

Under the hood this settles funding for every AMM registered in the clearing house:

```solidity
(_premiumFraction, _underlyingPrice, _cumulativePremiumFraction, _nextFundingTime) = amms[i].settleFunding();
```

This call increases the `cumulativePremiumFraction` by `premiumFraction` for the respective AMM as defined by this formula:

```solidity
        // premium = twapMarketPrice - twapIndexPrice
        // timeFraction = fundingPeriod(1 hour) / 1 day
        // premiumFraction = premium * timeFraction
```

Now, the `cumulativePremiumFraction` variable is used in the method `getPendingFundingPayment` which is called by `updatePosition`. The top level call for this flow can be found in `ClearingHouse.sol`:

```solidity
function updatePositions(address trader) override public whenNotPaused {
        require(address(trader) != address(0), 'CH: 0x0 trader Address');
        // lastFundingTime will always be >= lastFundingPaid[trader]
        if (lastFundingPaid[trader] != lastFundingTime) {
            int256 fundingPayment;
            uint numAmms = amms.length;
            for (uint i; i < numAmms; ++i) {
                (int256 _fundingPayment, int256 cumulativePremiumFraction) = amms[i].updatePosition(trader);
                if (_fundingPayment != 0) {
                    fundingPayment += _fundingPayment;
                    emit FundingPaid(trader, i, _fundingPayment, cumulativePremiumFraction);
                }
            }
            // -ve fundingPayment means trader should receive funds
            marginAccount.realizePnL(trader, -fundingPayment);
            lastFundingPaid[trader] = lastFundingTime;
        }
    }
```

As can be seen from this method, the funding payments are used to realise any change in the VUSD margin for the trader in question. Therefore, deciding not to call `settleFunding` will result in no funding payments being applied and the margin of trader accounts remaining unchanged. This can be used to negatively impact traders that should be getting an increase in margin, and more interestingly it could be used by a set of validators that are colluding to make trades with no funding payments applied.

## Impact
By not calling `settleFunding` the margin of a trader's account isn't kept up to date. As a result a trader's account could actually be kept in a net-positive margin position to avoid being liquidated, despite the fact that the account should actually have to settle funding payments based on their positions. This positively impacts half the market and negatively impact the other half of the market and thus can be used by validators to their own advantage without changing the apparent health of the protocol.

## Code Snippet
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/orderbooks/OrderBook.sol#L399-L401
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/ClearingHouse.sol#L267
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/AMM.sol#L236-L271
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/AMM.sol#L203-L214
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/ClearingHouse.sol#L248-L255

## Tool used
Manual Review

## Recommendation
Just removing the `onlyValidator` guard from the `settleFunding` method in `OrderBook.sol` is not enough because a set of colluding validators could still choose to exclude any transactions from proposed blocks that call this method.

Instead, funding should be settled during calls to `updatePositions` in `ClearingHouse.sol`. This way, a colluding set of validators would not be able to manage positions or remove margin without applying funding payments. Below is a diff with my suggested change:

```diff
diff --git a/hubble-protocol/contracts/ClearingHouse.sol b/hubble-protocol/contracts/ClearingHouse.sol
index 53caead..3297930 100644
--- a/hubble-protocol/contracts/ClearingHouse.sol
+++ b/hubble-protocol/contracts/ClearingHouse.sol
@@ -239,6 +239,7 @@ contract ClearingHouse is IClearingHouse, HubbleBase {
      * it is not strictly necessary to call this function on every trade for a trader, however we still currently do so. Might explore avoiding this in the future.
     */
     function updatePositions(address trader) override public whenNotPaused {
+        settleFunding();
         require(address(trader) != address(0), 'CH: 0x0 trader Address');
         // lastFundingTime will always be >= lastFundingPaid[trader]
         if (lastFundingPaid[trader] != lastFundingTime) {
@@ -257,7 +258,7 @@ contract ClearingHouse is IClearingHouse, HubbleBase {
         }
     }
 
-    function settleFunding() override external onlyDefaultOrderBook {
+    function settleFunding() override public {
         uint numAmms = amms.length;
         uint _nextFundingTime;
         for (uint i; i < numAmms; ++i) {

```