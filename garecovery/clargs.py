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
DEFAULT_OFILE = 'garecovery.csv'


def default_tx_cache_filename():
    return os.path.expanduser('~/.garecovery_txcache')


args = None


def set_args(argv):
    global args
    args = get_args(argv)


def get_args(argv):
    parser = argparse.ArgumentParser(
        description="GreenAddress command line recovery tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        'recovery_mode',
        choices=['2of2'],
        default='2of2',
        help='Type of recovery to perform')
    parser.add_argument(
        '--mnemonic-file',
        dest='mnemonic_file',
        help="Name of file containing the user's mnemonic")
    parser.add_argument(
        '-o', '--output-file',
        default=DEFAULT_OFILE,
        help='Output file for csv data')
    parser.add_argument(
        '-s', '--show-summary',
        dest='show_summary',
        action='store_true',
        help='Show a summary of the transactions available to recover')
    parser.add_argument(
        '--units',
        choices=['BTC', 'mBTC', 'uBTC', 'bit', 'sat'],
        default='BTC',
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
        '--default-feerate',
        dest='default_feerate',
        type=int,
        default=5,
        help='Fee rate (satoshis per byte)')

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

    two_of_two = parser.add_argument_group('2of2 options')

    # two_of_two.add_argument(
    #     '--satoshis',
    #     type=int,
    #     help='Exact number of Satoshis (BTC * 10^8) ending up in your GA wallet after the transaction. https://www.screencast.com/t/zNHS9vVXYlGP')
    # two_of_two.add_argument(
    #     '--ga-address-pointer',
    #     type=int,
    #     help='Index of the transaction in your GreenAddress history. First transaction is 1, second is 2, and so on.')

    argcomplete.autocomplete(parser)
    result = parser.parse_args(argv[1:])

    def optval(name):
        attrname = name.replace('-', '_').replace('__', '')
        return getattr(result, attrname, None)

    def arg_required(name, display_names=None):
        if optval(name) is None:
            name = name if display_names is None else display_names
            parser.error('%s required for mode %s' % (name, result.recovery_mode))

    def arg_disallowed(name):
        if optval(name) is not None:
            parser.error('%s not allowed for mode %s' % (name, result.recovery_mode))

    if result.recovery_mode == '2of2':
        #arg_required('--satoshis')
        #arg_required('--ga-address-pointer')
        #arg_required('--destination-address')
        for arg in ['--ga-xpub', '--search-subaccounts',
                    '--recovery-mnemonic-file', '--custom-xprv']:
            arg_disallowed(arg)

    result.login_data = None
    return result
