yixxas

high

# Cancelling `reduceOnly` orders that are partially filled does not release margin

## Summary
When orders are partially filled, and then cancelled after, the amount that has not been filled should be released from margin requirement. Otherwise, user will have an understated `margin` amount and hence will not be able to open as many orders as they should be able to.

## Vulnerability Detail

As we can observe in `_cancelOrder()`, `releaseMargin` is only set if the order is not a `reduceOnly` order. In the case where an order is `reduceOnly`, it is possible for the order to be partially filled. In this case, margin should also be released after an order is cancelled, since an order that is placed to reduce order, but not filled completely and then cancelled should increase back the margin to the user that has previously "spent" some amount of margin to open this position. The amount of margin to be released should be the remaining unfilled amount.

```solidity
    function _cancelOrder(Order memory order) internal returns (uint releaseMargin) {
        bytes32 orderHash = getOrderHash(order);
        require(orderInfo[orderHash].status == OrderStatus.Placed, "OB_Order_does_not_exist");

        address trader = order.trader;
        if (msg.sender != trader) {
            require(isValidator[msg.sender], "OB_invalid_sender");
            // allow cancellation of order by validator if availableMargin < 0
            // there is more information in the description of the function
            require(marginAccount.getAvailableMargin(trader) < 0, "OB_available_margin_not_negative");
        }

        orderInfo[orderHash].status = OrderStatus.Cancelled;
        if (order.reduceOnly) {
            int unfilledAmount = abs(order.baseAssetQuantity - orderInfo[orderHash].filledAmount);
            reduceOnlyAmount[trader][order.ammIndex] -= unfilledAmount;
        } else {
            releaseMargin = orderInfo[orderHash].reservedMargin;
        }

        _deleteOrderInfo(orderHash);
        emit OrderCancelled(trader, orderHash, block.timestamp);
    }
```

## Impact
Users have an understated `margin` amount and hence can open a smaller position than they should be able to.

## Code Snippet
https://github.com/hubble-exchange/hubble-protocol/blob/3a6b576eeedc323c70feb3808c665228e5f9b8a5/contracts/orderbooks/OrderBook.sol#L197-L202

## Tool used

Manual Review

## Recommendation
Set `releaseMargin = unfilledAmount` when orders are cancelled if order is a `reduceOnly` order.
