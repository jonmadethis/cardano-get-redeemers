# Cardano Smart Contract Redeemer Fetcher

A Python tool for fetching and analyzing redeemer data from Cardano smart contracts using the Blockfrost API and PyCardano utilities.

This script makes it easy to pull and inspect the data that Cardano smart contracts use when they spend funds. It connects to the Blockfrost API and uses PyCardano utilities to fetch every redeemer submitted to a given script address. Along with the raw redeemer data you get details on CPU steps and memory usage, the transaction inputs carrying each redeemer, and a summary of script performance. You can use it to debug complex on-chain interactions, verify that your Plutus logic is working as expected, or gather metrics for optimization.

## Features

- ✅ Fetch UTXOs from Cardano smart contract addresses
- ✅ Extract redeemer hashes from contract transactions
- ✅ Retrieve detailed redeemer data including JSON and CBOR values
- ✅ Validate Cardano addresses (both bech32 and hex formats)
- ✅ Support for both mainnet and testnet networks
- ✅ Comprehensive logging and error handling
- ✅ JSON output with summary statistics
- ✅ Rate limiting to respect API limits

## Prerequisites

- Python 3.7+
- A Blockfrost API project ID ([Get one here](https://blockfrost.io))

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Setup

### Get a Blockfrost Project ID

1. Sign up at [blockfrost.io](https://blockfrost.io)
2. Create a new project
3. Copy your project ID

### Set your Project ID

You can provide your Blockfrost project ID in two ways:

**Option 1: Environment Variable (Recommended)**
```bash
export BLOCKFROST_PROJECT_ID=your_project_id_here
```

**Option 2: Command Line Argument**
```bash
python get_redeemer.py --project-id your_project_id_here --address addr1...
```

## Usage

### Basic Usage

```bash
python get_redeemer.py --address addr1qxy2kv0ynwvuqvfz4d8w20pvd8v9u8t2hnhj0nv8kq4hspjf8rnzmjxr4y4r8tx9x3lv0s4hrz4n0xp0l6h9u4d0n4yq7l4nk3
```

### Advanced Usage

```bash
# Limit the number of redeemers fetched
python get_redeemer.py --address addr1... --limit 10

# Use testnet instead of mainnet
python get_redeemer.py --address addr_test1... --network testnet

# Save output to file
python get_redeemer.py --address addr1... --output results.json

# Enable debug logging
python get_redeemer.py --address addr1... --log-level DEBUG

# Combine multiple options
python get_redeemer.py \
  --address addr1... \
  --limit 50 \
  --network mainnet \
  --output contract_analysis.json \
  --log-level INFO \
  --project-id your_project_id
```

## Command Line Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--address` | Yes | Cardano smart contract address (bech32 format) |
| `--project-id` | * | Blockfrost project ID (or set `BLOCKFROST_PROJECT_ID` env var) |
| `--limit` | No | Maximum number of redeemers to fetch |
| `--network` | No | Network to use: `mainnet` or `testnet` (default: mainnet) |
| `--log-level` | No | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: DEBUG) |
| `--output` | No | Output file for JSON results (default: stdout) |

\* Required unless set as environment variable

## Output Format

The script outputs a JSON object with the following structure:

```json
{
  "contract_address": "addr1...",
  "script_hash": "abcd1234...",
  "utxo_count": 42,
  "redeemer_count": 15,
  "redeemers": [
    {
      "hash": "ef567890...",
      "json_value": {...},
      "cbor_value": "...",
      "bytes": "..."
    }
  ],
  "summary": {
    "purposes": {
      "spend": 10,
      "mint": 3,
      "cert": 2
    },
    "total_fees": 1500000,
    "total_memory_units": 50000000,
    "total_cpu_steps": 25000000000,
    "script_hashes": ["hash1", "hash2"],
    "unique_script_count": 2
  }
}
```

## Error Handling

The script includes comprehensive error handling for:

- Invalid Cardano addresses
- Network connectivity issues
- API rate limits
- Missing redeemer data
- Malformed responses

## Examples

### Example 1: Basic Contract Analysis

```bash
python get_redeemer.py --address addr1qxy2kv0ynwvuqvfz4d8w20pvd8v9u8t2hnhj0nv8kq4hspjf8rnzmjxr4y4r8tx9x3lv0s4hrz4n0xp0l6h9u4d0n4yq7l4nk3
```

### Example 2: Limited Analysis with File Output

```bash
python get_redeemer.py \
  --address addr1... \
  --limit 5 \
  --output my_contract_analysis.json
```

### Example 3: Testnet Contract

```bash
python get_redeemer.py \
  --address addr_test1... \
  --network testnet \
  --project-id your_testnet_project_id
```

## Troubleshooting

### Common Issues

**"Blockfrost project ID is required"**
- Solution: Set the `BLOCKFROST_PROJECT_ID` environment variable or use `--project-id`

**"Address validation failed"**
- Check that the address format is correct (starts with `addr1` for mainnet or `addr_test1` for testnet)
- Ensure the address matches the selected network
- Verify the address is not truncated or corrupted

**"No UTXOs found"**
- The contract may not have any UTXOs at the current time
- Verify the address is a valid smart contract address
- Check if you're using the correct network (mainnet vs testnet)

**API Rate Limiting**
- The script includes built-in rate limiting (0.1s between requests)
- If you encounter rate limit errors, try reducing the `--limit` parameter

### Debug Mode

Enable debug logging to see detailed information about the processing:

```bash
python get_redeemer.py --address addr1... --log-level DEBUG
```

## Dependencies

- `blockfrost-python`: Blockfrost API client
- `pycardano`: Cardano Python library for address handling
- `requests`: HTTP library for API calls

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## License

This project is open source. Please check the license file for details.

## Acknowledgments

- [Blockfrost](https://blockfrost.io) for providing the Cardano API
- [PyCardano](https://github.com/Python-Cardano/pycardano) for Cardano utilities
- My buddy [Claude](https://claude.ai/), because he's smarter than me 
- The Cardano community for documentation and support
