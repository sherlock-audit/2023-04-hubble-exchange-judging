0x52

medium

# MarginAccountHelper will be bricked if registry.marginAccount or insuranceFund ever change

## Summary

MarginAccountHelper#syncDeps causes the contract to refresh it's references to both marginAccount and insuranceFund. The issue is that approvals are never made to the new contracts rendering them useless.

## Vulnerability Detail

[MarginAccountHelper.sol#L82-L87](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccountHelper.sol#L82-L87)

    function syncDeps(address _registry) public onlyGovernance {
        IRegistry registry = IRegistry(_registry);
        vusd = IVUSD(registry.vusd());
        marginAccount = IMarginAccount(registry.marginAccount());
        insuranceFund = IInsuranceFund(registry.insuranceFund());
    }

When syncDeps is called the marginAccount and insuranceFund references are updated. All transactions require approvals to one of those two contract. Since no new approvals are made, the contract will become bricked and all transactions will revert.

## Impact

Contract will become bricked and all contracts that are integrated or depend on it will also be bricked

## Code Snippet

[MarginAccountHelper.sol#L82-L87](https://github.com/sherlock-audit/2023-04-hubble-exchange/blob/main/hubble-protocol/contracts/MarginAccountHelper.sol#L82-L87)

## Tool used

Manual Review

## Recommendation

Remove approvals to old contracts before changing and approve new contracts after