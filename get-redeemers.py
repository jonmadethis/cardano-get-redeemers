#!/usr/bin/env python3
"""
Cardano Smart Contract Redeemer Fetcher

This script fetches and analyzes redeemer data from Cardano smart contracts
using the Blockfrost API and PyCardano utilities.

Claude was used to write this script.
"""

import argparse
import json
import logging
import sys
from typing import List, Dict, Any, Optional, Tuple
import time

try:
    from blockfrost import BlockFrostApi, ApiError, ApiUrls
    from pycardano import Address, PlutusV1Script, PlutusV2Script, script_hash
    import requests
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install dependencies with: pip install -r requirements.txt")
    print("\nTo install:")
    print("pip install blockfrost-python pycardano requests")
    sys.exit(1)


class CardanoRedeemerFetcher:
    """Main class for fetching Cardano contract redeemer data."""
    
    def __init__(self, blockfrost_project_id: str, network: str = "mainnet"):
        """Initialize the fetcher with Blockfrost API credentials."""
        self.network = network
        self.api_url = ApiUrls.mainnet.value if network == "mainnet" else ApiUrls.testnet.value
        
        try:
            self.api = BlockFrostApi(
                project_id=blockfrost_project_id,
                base_url=self.api_url
            )
        except Exception as e:
            logging.error(f"Failed to initialize Blockfrost API: {e}")
            raise
        
        self.logger = logging.getLogger(__name__)
    
    def validate_address(self, address_str: str) -> Tuple[bool, str]:
        """
        Validate if the provided string is a valid Cardano address.
        Returns (is_valid, error_message)
        """
        # Basic checks first
        if not address_str:
            return False, "Address cannot be empty"
        
        if len(address_str) < 10:
            return False, "Address too short"
        
        if len(address_str) > 200:
            return False, "Address too long"
        
        # Check if it looks like a Cardano address
        if not (address_str.startswith('addr1') or address_str.startswith('addr_test1') or 
                (len(address_str) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in address_str))):
            return False, "Address doesn't match Cardano format (should start with 'addr1' or 'addr_test1', or be valid hex)"
        
        try:
            # Try PyCardano decode method for bech32
            addr = Address.decode(address_str)
            self.logger.debug(f"Successfully parsed address with decode(): {addr}")
            self.logger.debug(f"Address network: {addr.network}")
            self.logger.debug(f"Address type: {type(addr)}")
            return True, "Valid address"
        except Exception as e:
            self.logger.debug(f"Address.decode() failed: {e}")
            try:
                # Try PyCardano from_primitive method (handles both bech32 and hex)
                addr = Address.from_primitive(address_str)
                self.logger.debug(f"Successfully parsed address with from_primitive(): {addr}")
                return True, "Valid address"
            except Exception as e2:
                self.logger.debug(f"Address.from_primitive() failed: {e2}")
                try:
                    # Try from_primitive with hex bytes
                    if len(address_str) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in address_str):
                        addr = Address.from_primitive(bytes.fromhex(address_str))
                        self.logger.debug(f"Successfully parsed hex address: {addr}")
                        return True, "Valid hex address"
                    else:
                        return False, f"Invalid address format. decode() error: {str(e)}, from_primitive() error: {str(e2)}"
                except Exception as e3:
                    self.logger.debug(f"Hex validation failed: {e3}")
                    return False, f"Invalid address format. decode() error: {str(e)}, from_primitive() error: {str(e2)}, hex error: {str(e3)}"
    
    def compute_script_hash(self, contract_address: str) -> str:
        """
        Extract the script hash from a contract address.
        For script addresses, this extracts the payment part hash.
        """
        try:
            # Parse the address to extract script hash
            try:
                addr = Address.decode(contract_address)
            except Exception:
                # Fallback to from_primitive
                addr = Address.from_primitive(contract_address)
            
            self.logger.debug(f"Parsed address: {addr}")
            self.logger.debug(f"Address type: {type(addr)}")
            self.logger.debug(f"Payment part: {addr.payment_part}")
            self.logger.debug(f"Payment part type: {type(addr.payment_part)}")
            
            if addr.payment_part is None:
                raise ValueError("Address does not contain a payment part")
            
            # Extract the hash from the payment part
            if hasattr(addr.payment_part, 'payload'):
                script_hash_hex = addr.payment_part.payload.hex()
            elif hasattr(addr.payment_part, 'hash'):
                script_hash_hex = addr.payment_part.hash.hex()
            else:
                # Fallback: convert the payment part directly
                script_hash_hex = bytes(addr.payment_part).hex()
            
            self.logger.info(f"Extracted script hash: {script_hash_hex}")
            return script_hash_hex
            
        except Exception as e:
            self.logger.error(f"Failed to compute script hash: {e}")
            raise
    
    def fetch_script_utxos(self, contract_address: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch all UTXOs for a given contract address."""
        self.logger.info(f"Fetching UTXOs for contract address: {contract_address}")
        
        try:
            # Fetch UTXOs directly from the contract address
            utxos = []
            page = 1
            page_size = 100
            
            while True:
                try:
                    batch = self.api.address_utxos(
                        address=contract_address,
                        count=page_size,
                        page=page
                    )
                    
                    if not batch:
                        break
                    
                    utxos.extend(batch)
                    
                    if limit and len(utxos) >= limit:
                        utxos = utxos[:limit]
                        break
                    
                    if len(batch) < page_size:
                        break
                    
                    page += 1
                    time.sleep(0.1)  # Rate limiting
                    
                except ApiError as e:
                    if e.status_code == 404:
                        self.logger.warning("No UTXOs found for this address")
                        break
                    else:
                        raise
            
            self.logger.info(f"Found {len(utxos)} UTXOs")
            return utxos
            
        except Exception as e:
            self.logger.error(f"Failed to fetch UTXOs: {e}")
            raise
    
    def extract_redeemer_hashes(self, utxos: List[Dict[str, Any]]) -> tuple[List[str], Dict[str, Any]]:
        """Extract redeemer hashes from UTXO data and collect summary statistics."""
        redeemer_hashes = []
        summary_stats = {
            'purposes': {},
            'total_fees': 0,
            'total_memory_units': 0,
            'total_cpu_steps': 0,
            'script_hashes': set()
        }
        
        # Debug: inspect the first UTXO to understand the structure
        if utxos and self.logger.isEnabledFor(logging.DEBUG):
            first_utxo = utxos[0]
            self.logger.debug(f"First UTXO type: {type(first_utxo)}")
            self.logger.debug(f"First UTXO attributes: {dir(first_utxo) if hasattr(first_utxo, '__dict__') else 'No __dict__'}")
            if hasattr(first_utxo, '__dict__'):
                self.logger.debug(f"First UTXO content: {first_utxo.__dict__}")
            elif hasattr(first_utxo, '_asdict'):
                self.logger.debug(f"First UTXO content: {first_utxo._asdict()}")
        
        for utxo in utxos:
            try:
                # Handle both dict and Namespace objects from Blockfrost
                if hasattr(utxo, 'tx_hash'):
                    tx_hash = utxo.tx_hash
                elif isinstance(utxo, dict):
                    tx_hash = utxo.get('tx_hash')
                else:
                    self.logger.debug(f"Unexpected UTXO type: {type(utxo)}")
                    continue
                
                if tx_hash:
                    self.logger.debug(f"Processing transaction: {tx_hash}")
                    # Get transaction details to find redeemers
                    tx_redeemers, tx_stats = self.get_transaction_redeemers(tx_hash)
                    redeemer_hashes.extend(tx_redeemers)
                    
                    # Merge summary statistics
                    for purpose, count in tx_stats['purposes'].items():
                        summary_stats['purposes'][purpose] = summary_stats['purposes'].get(purpose, 0) + count
                    summary_stats['total_fees'] += tx_stats['total_fees']
                    summary_stats['total_memory_units'] += tx_stats['total_memory_units']
                    summary_stats['total_cpu_steps'] += tx_stats['total_cpu_steps']
                    summary_stats['script_hashes'].update(tx_stats['script_hashes'])
                    
                    # Alternative approach: look for datum hashes in the UTXO itself
                    # Some UTXOs may have inline datums or datum hashes
                    self.extract_datum_from_utxo(utxo, redeemer_hashes)
                    
                    # Also check if this transaction spent from script addresses
                    # (where redeemers would be used)
                    self.check_transaction_inputs(tx_hash, redeemer_hashes)
                    
            except Exception as e:
                self.logger.warning(f"Failed to extract redeemer from UTXO: {e}")
                self.logger.debug(f"UTXO object type: {type(utxo)}")
                continue
        
        # Remove duplicates while preserving order
        unique_hashes = list(dict.fromkeys(redeemer_hashes))
        self.logger.info(f"Found {len(unique_hashes)} unique redeemer hashes")
        
        # Convert set to list for JSON serialization
        summary_stats['script_hashes'] = list(summary_stats['script_hashes'])
        summary_stats['unique_script_count'] = len(summary_stats['script_hashes'])
        
        return unique_hashes, summary_stats
    
    def extract_datum_from_utxo(self, utxo, redeemer_hashes: List[str]) -> None:
        """Extract datum hashes directly from UTXO if present."""
        try:
            # Look for datum hash in UTXO
            datum_hash = None
            if hasattr(utxo, 'data_hash'):
                datum_hash = utxo.data_hash
            elif hasattr(utxo, 'datum_hash'):
                datum_hash = utxo.datum_hash
            elif isinstance(utxo, dict):
                datum_hash = utxo.get('data_hash') or utxo.get('datum_hash')
            
            if datum_hash and datum_hash not in redeemer_hashes:
                self.logger.debug(f"Found datum hash in UTXO: {datum_hash}")
                redeemer_hashes.append(datum_hash)
                
            # Look for inline datum
            inline_datum = None
            if hasattr(utxo, 'inline_datum'):
                inline_datum = utxo.inline_datum
            elif isinstance(utxo, dict):
                inline_datum = utxo.get('inline_datum')
                
            if inline_datum:
                self.logger.debug(f"Found inline datum in UTXO: {inline_datum}")
                # Note: inline datums don't have hashes, but we could process them differently
                
        except Exception as e:
            self.logger.debug(f"Error extracting datum from UTXO: {e}")
    
    def check_transaction_inputs(self, tx_hash: str, redeemer_hashes: List[str]) -> None:
        """Check transaction inputs for script spending that would use redeemers."""
        try:
            # Get transaction UTXOs (inputs and outputs)
            tx_utxos = self.api.transaction_utxos(tx_hash)
            
            if hasattr(tx_utxos, 'inputs'):
                inputs = tx_utxos.inputs
            elif isinstance(tx_utxos, dict):
                inputs = tx_utxos.get('inputs', [])
            else:
                self.logger.debug(f"Unexpected tx_utxos type: {type(tx_utxos)}")
                return
            
            for tx_input in inputs:
                # Look for script addresses in inputs (these would need redeemers)
                input_address = None
                if hasattr(tx_input, 'address'):
                    input_address = tx_input.address
                elif isinstance(tx_input, dict):
                    input_address = tx_input.get('address')
                
                if input_address and (input_address.startswith('addr1') and len(input_address) > 100):
                    # This looks like a script address (they're typically longer)
                    self.logger.debug(f"Found script input address: {input_address}")
                    # The redeemer for this input should be in the transaction_redeemers
                    # which we already checked, but this confirms script usage
                    
        except ApiError as e:
            if e.status_code == 404:
                self.logger.debug(f"No UTXO data found for tx {tx_hash}")
            else:
                self.logger.debug(f"Error getting transaction UTXOs for {tx_hash}: {e}")
        except Exception as e:
            self.logger.debug(f"Error checking transaction inputs for {tx_hash}: {e}")
    
    def get_transaction_redeemers(self, tx_hash: str) -> tuple[List[str], Dict[str, Any]]:
        """Get redeemer hashes from a specific transaction and collect statistics."""
        try:
            redeemers = self.api.transaction_redeemers(tx_hash)
            redeemer_hashes = []
            stats = {
                'purposes': {},
                'total_fees': 0,
                'total_memory_units': 0,
                'total_cpu_steps': 0,
                'script_hashes': set()
            }
            
            # Debug: inspect the redeemers structure
            if redeemers and self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Found {len(redeemers)} redeemers for tx {tx_hash}")
                first_redeemer = redeemers[0]
                self.logger.debug(f"First redeemer type: {type(first_redeemer)}")
                self.logger.debug(f"First redeemer attributes: {dir(first_redeemer) if hasattr(first_redeemer, '__dict__') else 'No __dict__'}")
                if hasattr(first_redeemer, '__dict__'):
                    self.logger.debug(f"First redeemer content: {first_redeemer.__dict__}")
                elif hasattr(first_redeemer, '_asdict'):
                    self.logger.debug(f"First redeemer content: {first_redeemer._asdict()}")
            
            for redeemer in redeemers:
                try:
                    # Handle both dict and Namespace objects
                    if hasattr(redeemer, 'datum_hash'):
                        datum_hash = redeemer.datum_hash
                    elif isinstance(redeemer, dict):
                        datum_hash = redeemer.get('datum_hash')
                    else:
                        self.logger.debug(f"Unexpected redeemer type: {type(redeemer)}")
                        continue
                    
                    if datum_hash:
                        redeemer_hashes.append(datum_hash)
                        
                    # Also look for redeemer_data_hash or other hash fields
                    for attr_name in ['redeemer_data_hash', 'data_hash', 'hash']:
                        if hasattr(redeemer, attr_name):
                            hash_value = getattr(redeemer, attr_name)
                            if hash_value and hash_value not in redeemer_hashes:
                                redeemer_hashes.append(hash_value)
                        elif isinstance(redeemer, dict) and attr_name in redeemer:
                            hash_value = redeemer[attr_name]
                            if hash_value and hash_value not in redeemer_hashes:
                                redeemer_hashes.append(hash_value)
                    
                    # Collect statistics
                    purpose = None
                    if hasattr(redeemer, 'purpose'):
                        purpose = redeemer.purpose
                    elif isinstance(redeemer, dict):
                        purpose = redeemer.get('purpose')
                    
                    if purpose:
                        stats['purposes'][purpose] = stats['purposes'].get(purpose, 0) + 1
                    
                    # Collect fees, memory units, and CPU steps
                    for field, stat_key in [('fee', 'total_fees'), ('unit_mem', 'total_memory_units'), ('unit_steps', 'total_cpu_steps')]:
                        value = None
                        if hasattr(redeemer, field):
                            value = getattr(redeemer, field)
                        elif isinstance(redeemer, dict):
                            value = redeemer.get(field)
                        
                        if value:
                            try:
                                stats[stat_key] += int(value)
                            except (ValueError, TypeError):
                                pass
                    
                    # Collect script hash
                    script_hash = None
                    if hasattr(redeemer, 'script_hash'):
                        script_hash = redeemer.script_hash
                    elif isinstance(redeemer, dict):
                        script_hash = redeemer.get('script_hash')
                    
                    if script_hash:
                        stats['script_hashes'].add(script_hash)
                                
                except Exception as e:
                    self.logger.debug(f"Error processing individual redeemer: {e}")
                    continue
                    
            return redeemer_hashes, stats
            
        except ApiError as e:
            if e.status_code == 404:
                self.logger.debug(f"No redeemers found for tx {tx_hash} (404)")
                return [], {'purposes': {}, 'total_fees': 0, 'total_memory_units': 0, 'total_cpu_steps': 0, 'script_hashes': set()}
            else:
                self.logger.warning(f"Failed to get redeemers for tx {tx_hash}: {e}")
                return [], {'purposes': {}, 'total_fees': 0, 'total_memory_units': 0, 'total_cpu_steps': 0, 'script_hashes': set()}
        except Exception as e:
            self.logger.warning(f"Error processing transaction {tx_hash}: {e}")
            return [], {'purposes': {}, 'total_fees': 0, 'total_memory_units': 0, 'total_cpu_steps': 0, 'script_hashes': set()}
    
    def fetch_redeemer_details(self, redeemer_hashes: List[str]) -> List[Dict[str, Any]]:
        """Fetch detailed redeemer information for each hash."""
        redeemer_details = []
        
        for i, redeemer_hash in enumerate(redeemer_hashes):
            self.logger.info(f"Fetching redeemer {i+1}/{len(redeemer_hashes)}: {redeemer_hash}")
            
            try:
                # Get redeemer details
                redeemer_data = self.api.script_datum(redeemer_hash)
                
                # Handle both dict and Namespace objects
                redeemer_info = {
                    'hash': redeemer_hash,
                    'json_value': None,
                    'cbor_value': None,
                    'bytes': None
                }
                
                # Extract data from either dict or Namespace object
                if hasattr(redeemer_data, 'to_dict'):
                    # Convert Namespace to dict first
                    data_dict = redeemer_data.to_dict()
                    redeemer_info['json_value'] = data_dict.get('json_value')
                    redeemer_info['cbor_value'] = data_dict.get('cbor_value')
                    redeemer_info['bytes'] = data_dict.get('bytes')
                elif hasattr(redeemer_data, 'json_value'):
                    redeemer_info['json_value'] = redeemer_data.json_value
                elif isinstance(redeemer_data, dict):
                    redeemer_info['json_value'] = redeemer_data.get('json_value')
                
                if hasattr(redeemer_data, 'cbor_value') and not redeemer_info['cbor_value']:
                    redeemer_info['cbor_value'] = redeemer_data.cbor_value
                elif isinstance(redeemer_data, dict) and not redeemer_info['cbor_value']:
                    redeemer_info['cbor_value'] = redeemer_data.get('cbor_value')
                
                if hasattr(redeemer_data, 'bytes') and not redeemer_info['bytes']:
                    redeemer_info['bytes'] = redeemer_data.bytes
                elif isinstance(redeemer_data, dict) and not redeemer_info['bytes']:
                    redeemer_info['bytes'] = redeemer_data.get('bytes')
                
                redeemer_details.append(redeemer_info)
                time.sleep(0.1)  # Rate limiting
                
            except ApiError as e:
                if e.status_code == 404:
                    self.logger.warning(f"Redeemer data not found for hash: {redeemer_hash}")
                else:
                    self.logger.error(f"API error fetching redeemer {redeemer_hash}: {e}")
            except Exception as e:
                self.logger.error(f"Failed to fetch redeemer {redeemer_hash}: {e}")
        
        return redeemer_details
    
    def process_contract(self, contract_address: str, limit: Optional[int] = None) -> Dict[str, Any]:
        """Main method to process a contract and return all redeemer data."""
        results = {
            'contract_address': contract_address,
            'script_hash': None,
            'utxo_count': 0,
            'redeemer_count': 0,
            'redeemers': [],
            'summary': {
                'purposes': {},
                'total_fees': 0,
                'total_memory_units': 0,
                'total_cpu_steps': 0
            }
        }
        
        try:
            # Validate address
            is_valid, error_msg = self.validate_address(contract_address)
            if not is_valid:
                raise ValueError(f"Invalid Cardano address: {contract_address}. {error_msg}")
            
            # Compute script hash
            script_hash = self.compute_script_hash(contract_address)
            results['script_hash'] = script_hash
            
            # Fetch UTXOs
            utxos = self.fetch_script_utxos(contract_address, limit)
            results['utxo_count'] = len(utxos)
            
            if not utxos:
                self.logger.warning("No UTXOs found for this contract")
                return results
            
            # Extract redeemer hashes
            redeemer_hashes, summary_stats = self.extract_redeemer_hashes(utxos)
            results['summary'] = summary_stats
            
            if limit:
                redeemer_hashes = redeemer_hashes[:limit]
            
            results['redeemer_count'] = len(redeemer_hashes)
            
            if not redeemer_hashes:
                self.logger.warning("No redeemer hashes found")
                return results
            
            # Fetch redeemer details
            redeemer_details = self.fetch_redeemer_details(redeemer_hashes)
            results['redeemers'] = redeemer_details
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error processing contract: {e}")
            raise
    
    def convert_to_json_safe(self, obj):
        """Convert Namespace objects and other non-JSON-serializable objects to JSON-safe format."""
        if hasattr(obj, 'to_dict'):
            # Blockfrost Namespace objects have a to_dict() method
            return self.convert_to_json_safe(obj.to_dict())
        elif hasattr(obj, '__dict__'):
            # Convert objects with __dict__ to dictionaries
            return self.convert_to_json_safe(obj.__dict__)
        elif isinstance(obj, dict):
            # Recursively convert dictionary values
            return {key: self.convert_to_json_safe(value) for key, value in obj.items()}
        elif isinstance(obj, (list, tuple)):
            # Recursively convert list/tuple items
            return [self.convert_to_json_safe(item) for item in obj]
        else:
            # Return as-is for basic types (str, int, float, bool, None)
            return obj


def convert_to_json_safe(obj):
    """Convert Namespace objects and other non-JSON-serializable objects to JSON-safe format."""
    if hasattr(obj, 'to_dict'):
        # Blockfrost Namespace objects have a to_dict() method
        return convert_to_json_safe(obj.to_dict())
    elif hasattr(obj, '__dict__'):
        # Convert objects with __dict__ to dictionaries
        return convert_to_json_safe(obj.__dict__)
    elif isinstance(obj, dict):
        # Recursively convert dictionary values
        return {key: convert_to_json_safe(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        # Recursively convert list/tuple items
        return [convert_to_json_safe(item) for item in obj]
    else:
        # Return as-is for basic types (str, int, float, bool, None)
        return obj


def setup_logging(level: str = "INFO"):
    """Configure logging for the application."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Fetch redeemer data from Cardano smart contracts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python get_redeemers.py --address addr1... --limit 10
  python get_redeemers.py --address addr1... --project-id your_blockfrost_id
        """
    )
    
    parser.add_argument(
        '--address',
        required=True,
        help='Cardano smart contract address (bech32 format)'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Maximum number of redeemers to fetch (optional)'
    )
    
    parser.add_argument(
        '--project-id',
        help='Blockfrost project ID (or set BLOCKFROST_PROJECT_ID env var)'
    )
    
    parser.add_argument(
        '--network',
        choices=['mainnet', 'testnet'],
        default='mainnet',
        help='Cardano network to use (default: mainnet)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='DEBUG',  # Changed to DEBUG for better troubleshooting
        help='Logging level (default: DEBUG)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for JSON results (optional, defaults to stdout)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    # Test PyCardano functionality
    try:
        test_addr = "addr1qxy2kv0ynwvuqvfz4d8w20pvd8v9u8t2hnhj0nv8kq4hspjf8rnzmjxr4y4r8tx9x3lv0s4hrz4n0xp0l6h9u4d0n4yq7l4nk3"
        # Try the correct PyCardano methods
        try:
            Address.decode(test_addr)
            logger.debug("PyCardano Address.decode() test successful")
        except Exception:
            Address.from_primitive(test_addr)
            logger.debug("PyCardano Address.from_primitive() test successful")
    except Exception as e:
        logger.warning(f"PyCardano test failed: {e}, but continuing...")
    
    logger.info(f"Starting processing with log level: {args.log_level}")
    
    # Get Blockfrost project ID
    import os
    project_id = args.project_id or os.getenv('BLOCKFROST_PROJECT_ID')
    if not project_id:
        print("\n" + "="*60)
        print("ERROR: Blockfrost project ID is required!")
        print("="*60)
        print("Please either:")
        print("1. Use: --project-id YOUR_PROJECT_ID")
        print("2. Set environment variable: export BLOCKFROST_PROJECT_ID=YOUR_PROJECT_ID")
        print("\nTo get a project ID:")
        print("- Sign up at https://blockfrost.io")
        print("- Create a new project")
        print("- Copy your project ID")
        print("="*60)
        sys.exit(1)
    
    try:
        # Print the address as requested
        print(f"Processing contract address: {args.address}")
        
        # Initialize fetcher
        fetcher = CardanoRedeemerFetcher(project_id, args.network)
        
        # Test address validation first
        is_valid, error_msg = fetcher.validate_address(args.address)
        if not is_valid:
            logger.error(f"Address validation failed: {error_msg}")
            print(f"\nAddress validation failed: {error_msg}")
            print("\nPlease check:")
            print("1. Address format is correct (bech32: addr1... or addr_test1...)")
            print("2. Address is not corrupted or truncated")
            print("3. Address matches the selected network (mainnet/testnet)")
            sys.exit(1)
        
        logger.info("Address validation successful")
        
        # Process the contract
        results = fetcher.process_contract(args.address, args.limit)
        
        # Format and output results
        # Convert any Namespace objects to dictionaries for JSON serialization
        json_safe_results = convert_to_json_safe(results)
        output_json = json.dumps(json_safe_results, indent=2, ensure_ascii=False)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_json)
            logger.info(f"Results written to {args.output}")
        else:
            print("\n" + "="*50)
            print("RESULTS:")
            print("="*50)
            print(output_json)
        
        logger.info("Processing completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
