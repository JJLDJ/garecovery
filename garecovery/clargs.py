import argcomplete
import argparse
import logging
import os
import sys


# Define GreenAddress_T0 as the earliest possible GreenAddress UTXO
# This is used as the default value for scanning the blockchain
# 28 Feb 2014
GreenAddress_T0 = 1393545600

# Some defaults here make it easier for tests to override them
DEFAULT_SCAN_FROM = GreenAddress_T0
DEFAULT_KEY_SEARCH_DEPTH = 10000
DEFAULT_SUBACCOUNT_SEARCH_DEPTH = 10
DEFAULT_FEE_ESTIMATE_BLOCKS = 6


def default_tx_cache_filename():
    return os.path.expanduser('~/.garecovery_txcache')


args = None


def set_args(argv):
    global args
    args = get_args(argv)


def get_args(argv):
    parser = argparse.ArgumentParser(
        description="GreenAddress command line Single UTXO Bitcoin Cash (BCH) recovery tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        '--mnemonic-file',
        dest='mnemonic_file',
        help="Name of file containing the user's mnemonic")
    parser.add_argument(
        '-s', '--show-summary',
        dest='show_summary',
        action='store_true',
        help='Show a summary of the transactions available to recover')
    parser.add_argument(
        '--units',
        choices=['BCH', 'mBCH', 'uBCH', 'bit', 'sat'],
        default='BCH',
        dest='units',
        help='Units to display amounts')
    parser.add_argument(
        '--current-blockcount',
        dest='current_blockcount',
        type=int,
        help='Specify the current blockchain height')
    parser.add_argument(
        '-d', '-vv', '--debug',
        help="Print lots of debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING)
    parser.add_argument(
        '-v', '--verbose',
        help="Be verbose",
        action="store_const", dest="loglevel", const=logging.INFO)
    parser.add_argument(
        '--destination-address',
        help='An address to recover transactions to')
    parser.add_argument(
        '--total-fee-satoshis',
        dest='total_fee_satoshis',
        type=int,
        default=30000,
        help="Total TX fee in satoshis. Default is 30000 (0.0003 BCH), set unnecessarily high (~100 satoshis per byte), "
             "to be safe and to ensure the transaction gets processed immediately, and because it's what I used.")

    # TODO: Remove these if they're no longer needed.
    rpc = parser.add_argument_group('Bitcoin RPC options')
    rpc.add_argument(
        '--rpcuser',
        dest='rpcuser')
    rpc.add_argument(
        '--rpcpassword',
        dest='rpcpassword')
    rpc.add_argument(
        '--rpccookiefile',
        dest='rpccookiefile')
    rpc.add_argument(
        '--rpcconnect',
        dest='rpcconnect',
        default='127.0.0.1')
    rpc.add_argument(
        '--rpcport',
        dest='rpcport')
    rpc.add_argument(
        '--config-filename',
        dest='config_filename')
    rpc.add_argument(
        '--rpc-timeout-minutes',
        default=60,
        type=int,
        help='Timeout in minutes for rpc calls')

    # See build_single_utxo_signed_bch_tx docstring for more details on these options.
    parser.add_argument(
        '--redeem-script-hex',
        dest='redeem_script_hex',
        help="Hex string encoding of the full redeem script for the UTXO (unspent transaction) you're trying to spend. "
             "Should start with '52' and end with 'ae'.")
    parser.add_argument(
        '--tx-hash-hex',
        dest='tx_hash_hex',
        help="Hex string encoding of the transaction hash for the transaction containing the UTXO you're trying to spend. "
             "Example: e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70")
    parser.add_argument(
        '--utxo-address',
        dest='utxo_address',
        help="Address managed by GreenAddress that is currently holding your BCH. You can see these in the GreenAddress "
             "wallet GUI under Inputs/Outputs when you click on a transaction. Example: 3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA. "
             "Used to look up GreenAddress's internal pointer reference to the relevant private keys.")
    parser.add_argument(
        '--utxo-index',
        dest='utxo_index',
        type=int,
        help="Index (0-based) of the unspent transaction output in the list of outputs in the transaction you're trying to spend.")
    parser.add_argument(
        '--incoming-satoshis',
        dest='incoming_satoshis',
        type=int,
        help="Number of satoshis (BCH * 10^8) in the UTXO you want to spend, excluding fees. Should be the full amount "
             "in the UTXO. Example: 18232197")

    argcomplete.autocomplete(parser)
    result = parser.parse_args(argv[1:])

    def optval(name):
        attrname = name.replace('-', '_').replace('__', '')
        return getattr(result, attrname, None)

    def arg_required(name, display_names=None):
        if optval(name) is None:
            name = name if display_names is None else display_names
            parser.error('%s required' % (name))

    arg_required('--destination-address')
    arg_required('--redeem-script-hex')
    arg_required('--tx-hash-hex')
    arg_required('--utxo-address')
    arg_required('--utxo-index')
    arg_required('--incoming-satoshis')

    result.login_data = None
    return result
