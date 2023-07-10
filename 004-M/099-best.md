dirk_y

medium

# All assets are locked in MarginAccount if any supported asset value falls to 0

## Summary
If any supported asset price falls to 0 then no margin can be removed from the MarginAccount by any user (for any of the supported assets in the margin account).

## Vulnerability Detail
When a user wants to remove collateral from the `MarginAccount.sol` contract they call the `removeMargin` method that calls `_removeMarginFor` under the hood. During this call flow it is important to validate that the user has enough margin to cover all of their opened positions. This validation occurs in `_validateRemoveMargin`.

As part of this validation process the total value of the account's collateral is calculated in `weightedAndSpotCollateral`:

```solidity
        Collateral[] memory assets = supportedCollateral;
        Collateral memory _collateral;

        for (uint i; i < assets.length; i++) {
            if (margin[i][trader] == 0) continue;
            _collateral = assets[i];

            int numerator = margin[i][trader] * oracle.getUnderlyingPrice(address(assets[i].token));
            uint denomDecimals = _collateral.decimals;

            spot += (numerator / int(10 ** denomDecimals));
            weighted += (numerator * _collateral.weight.toInt256() / int(10 ** (denomDecimals + 6)));
        }
```

The interesting point above is that the method loops through every supported asset and fetches the latest price from the oracle. This call will fail if the price of the asset is 0 due to the following line in the oracle:

```solidity
require(answer > 0, "Oracle.getUnderlyingPrice.non_positive");
```

A similar call flow occurs during the `settleBadDebt` method, so the same bug will prevent the bad debt of an account being settled. Unfortunately there is no ability for Governance to remove a supported asset so this revert behaviour for all `removeMargin` calls will persist indefinitely.

## Impact
All assets will be locked in the MarginAccount contract if any of the supported assets fall to a price of 0.

## Code Snippet
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/Oracle.sol#L34
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccount.sol#L552-L561
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccount.sol#L646
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccount.sol#L605
https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccount.sol#L387

## Tool used
Manual Review

## Recommendation
A short term workaround for this is to set the stable price of the asset to a very small value. However manually specifying prices is actually an issue in itself and is discussed in another report.

A more logical solution is to add a `blacklistCollateral` method to the `MarginAccount.sol` contract to remove a collateral if necessary. To keep users of Hubble safe from governance centralisation, it could be worth having a check that a collateral can only be removed under certain circumstances (like when the price of the asset falls to 0).