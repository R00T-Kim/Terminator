# Protocol Vulnerabilities Index — Quick Reference Guide

**Created**: 2026-02-22
**Source**: `knowledge/protocol-vulns-index/` (cloned from kadenzipfel/protocol-vulnerabilities-index)

## Overview
- 460 vulnerability categories across 31 protocol types
- Each category file contains: description, examples, past exploits, detection patterns
- **analyst agent** loads the relevant category file based on target protocol type

## Protocol Type → Category File Mapping

| Target Protocol Type | Category Dir | Description |
|---------------------|-------------|-------------|
| DeFi Lending | `lending/` | Lending protocols |
| DEX / AMM | `dexes/` | Decentralized exchanges |
| Stablecoin (Algo) | `algo-stables/` | Algorithmic stablecoins |
| Stablecoin (Decentralized) | `decentralized-stablecoin/` | Decentralized stablecoins |
| Liquid Staking | `liquid-staking/` | Liquid staking derivatives |
| Bridge | `bridge/` | Single-chain bridges |
| Cross-chain | `cross-chain/` | Cross-chain protocols |
| Yield Farming | `leveraged-farming/` | Leveraged yield farming |
| Options Vault | `options-vault/` | Options/structured products |
| Derivatives | `derivatives/` | Derivatives/perpetuals |
| NFT Marketplace | `nft-marketplace/` | NFT trading platforms |
| NFT Lending | `nft-lending/` | NFT-collateralized lending |
| Insurance | `insurance/` | DeFi insurance |
| Launchpad | `launchpad/` | Token launchpads |
| Oracle | `oracle/` | Oracle protocols |
| CDP | `cdp/` | Collateralized debt positions |
| Yield Aggregator | `yield-aggregator/` | Yield aggregation |
| Yield | `yield/` | General yield protocols |
| Synthetics | `synthetics/` | Synthetic assets |
| Reserve Currency | `reserve-currency/` | Reserve currency protocols |
| RWA | `rwa/` | Real world assets |
| RWA Lending | `rwa-lending/` | RWA-backed lending |
| Staking Pool | `staking-pool/` | Staking protocols |
| Liquidity Manager | `liquidity-manager/` | LP management |
| Prediction Market | `prediction-market/` | Prediction markets |
| Privacy | `privacy/` | Privacy protocols |
| Gaming | `gaming/` | Blockchain gaming |
| Payments | `payments/` | Payment protocols |
| Services | `services/` | DeFi services |
| Indexes | `indexes/` | Index protocols |
| Uncollateralized Lending | `uncollateralized-lending/` | Flash loans / uncollateralized |

## Usage by analyst Agent

### Step 1: Identify Protocol Type
```bash
# From recon_report.json or program page:
# - "Lending protocol" → lending.md
# - "AMM / DEX" → dexes.md
# - "Liquid staking derivative" → liquid_staking.md
# - "Cross-chain bridge" → bridge.md + cross_chain.md
# - "Yield aggregator / ERC4626 vault" → leveraged_farming.md
```

### Step 2: Load Category Checklist
```bash
cat knowledge/protocol-vulns-index/categories/<type>.md
```

### Step 3: Cross-reference with Tool Results
```
For each category in the checklist:
  1. Does Slither detect this pattern? → Check slither_results.json
  2. Does the codebase contain the relevant functions? → grep
  3. Is this category known-issue for the protocol? → Check audit reports
  4. Score on Confidence Questionnaire if match found
```

## Top Vulnerability Categories by Protocol Type

### Lending (17 categories)
- Oracle manipulation / stale prices
- Liquidation MEV / sandwich
- Interest rate manipulation
- Flash loan price oracle attacks
- Collateral factor misconfiguration
- Bad debt accumulation

### DEX/AMM (19 categories)
- Sandwich attacks / MEV
- Impermanent loss exploitation
- Flash loan price manipulation
- LP share inflation attacks
- Fee-on-transfer token handling
- Reentrancy via callback tokens

### Liquid Staking (20 categories)
- Exchange rate manipulation
- Withdrawal queue attacks
- Slashing event handling
- Validator key management
- Rebasing vs non-rebasing token accounting

### Bridge/Cross-chain (18+20 categories)
- Message replay across chains
- Validator collusion / threshold attacks
- Nonce manipulation
- Token mapping errors
- Finality assumption violations
