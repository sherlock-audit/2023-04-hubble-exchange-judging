0x52

medium

# Malicious users can donate/leave dust amounts of collateral in contract during auctions to buy other collateral at very low prices

## Summary

Auctions are only ended early if the amount of the token being auctioned drops to 0. This can be exploited via donation or leaving dust in the contract to malicious extend the auction and buy further liquidate collateral at heavily discounted prices.

## Vulnerability Detail

[InsuranceFund.sol#L184-L199](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol#L184-L199)

    function buyCollateralFromAuction(address token, uint amount) override external {
        Auction memory auction = auctions[token];
        // validate auction
        require(_isAuctionOngoing(auction.startedAt, auction.expiryTime), "IF.no_ongoing_auction");

        // transfer funds
        uint vusdToTransfer = _calcVusdAmountForAuction(auction, token, amount);
        address buyer = _msgSender();
        vusd.safeTransferFrom(buyer, address(this), vusdToTransfer);
        IERC20(token).safeTransfer(buyer, amount); // will revert if there wasn't enough amount as requested

        // close auction if no collateral left
        if (IERC20(token).balanceOf(address(this)) == 0) { <- @audit-issue only cancels auction if balance = 0
            auctions[token].startedAt = 0;
        }
    }

When buying collateral from an auction, the auction is only closed if the balance of the token is 0. This can be exploited in a few ways to maliciously extend auctions and keep the timer (and price) decreasing. The first would be buy all but 1 wei of a token leaving it in the contract so the auction won't close. Since 1 wei isn't worth the gas costs to buy, there would be a negative incentive to buy the collateral, likely resulting in no on buying the final amount. A second approach would be to frontrun an buys with a single wei transfer with the same results.

Now that the auction has been extended any additional collateral added during the duration of the auction will start immediately well below the assets actual value. This allows malicious users to buy the asset for much cheaper, causing loss to the insurance fund.

## Impact

Users can maliciously extend auctions and potentially get collateral for very cheap

## Code Snippet

[InsuranceFund.sol#L184-L199](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/InsuranceFund.sol#L184-L199)

## Tool used

Manual Review

## Recommendation

Close the auction if there is less than a certain threshold of a token remaining after it has been bought:

        IERC20(token).safeTransfer(buyer, amount); // will revert if there wasn't enough amount as requested

    +   uint256 minRemainingBalance = 1 * 10 ** (IERC20(token).decimal() - 3);

        // close auction if no collateral left
    +   if (IERC20(token).balanceOf(address(this)) <= minRemainingBalance) {
            auctions[token].startedAt = 0;
        }