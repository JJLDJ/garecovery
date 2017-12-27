import base64
import logging
import os
import sys
from io import BytesIO

import pycoin.networks.default
import pycoin.tx.tx_utils
import pycoin.ui
from gacommon.utils import *
from gaservices.utils import inscript
from gaservices.utils.btc_ import tx_segwit_hash
from pycoin.tx.Spendable import Spendable
from pycoin.tx.Tx import Tx
from pycoin.tx.TxIn import TxIn
from pycoin.tx.TxOut import TxOut
from wallycore import *

from . import clargs
from . import exceptions
from . import formatting

# Python 2/3 compatibility
try:
    user_input = raw_input
except NameError:
    user_input = input

def do_login(mnemonics):
    conn = GAConnection(GAConnection.MAINNET_URI)

    # Convert our mnemonics into an HD wallet
    wallet = wallet_from_mnemonic(mnemonics)

    # Login the user. See gacommon/utils.py for the implementation
    return conn, wallet, login(wallet, conn, testnet=False)

def seed_from_mnemonic(mnemonic_or_hex_seed):
    """Return seed, mnemonic given an input string

    mnemonic_or_hex_seed can either be:
    - A mnemonic
    - A hex seed, with an 'X' at the end, which needs to be stripped

    seed will always be returned, mnemonic may be None if a seed was passed
    """
    if mnemonic_or_hex_seed.endswith('X'):
        mnemonic = None
        seed = hex_to_bytes(mnemonic_or_hex_seed[:-1])
    else:
        mnemonic = mnemonic_or_hex_seed
        written, seed = bip39_mnemonic_to_seed512(mnemonic_or_hex_seed, None)
        assert written == BIP39_SEED_LEN_512

    assert len(seed) == BIP39_SEED_LEN_512
    return seed, mnemonic


def wallet_from_mnemonic(mnemonic_or_hex_seed, ver=BIP32_VER_MAIN_PRIVATE):
    """Generate a BIP32 HD Master Key (wallet) from a mnemonic phrase or a hex seed"""
    seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed)
    return bip32_key_from_seed(seed, ver, BIP32_FLAG_SKIP_HASH)


def get_mnemonic(args, attr='mnemonic_file', prompt='mnemonic/hex seed: ', main=True):
    """Get a mnemonic/hex_seed either from file or from the console"""
    filename = getattr(args, attr)
    if not filename:
        mnemonic = user_input(prompt)
    else:
        mnemonic = open(filename).read()
    m = ' '.join(mnemonic.split())
    if main and len(mnemonic.split()) == 24:
        logging.warning("login greenaddress")
        args.conn, args.wallet, args.login_data = do_login(m)
        args.twofactor = args.conn.call('twofactor.get_config')

    return m


def main(argv=None):
    clargs.set_args(argv or sys.argv)
    logging.basicConfig(level=clargs.args.loglevel)

    try:
        # Open the csv output file before doing anything else in case it fails
        # Do not overwrite the output file if it already exists
        output_filename = clargs.args.output_file
        if os.path.exists(output_filename):
            raise exceptions.OfileExistsError(
                'Output file "{}" already exists, refusing to overwrite. Either remove the '
                'existing file or pass -o to specify a different output file'
                .format(output_filename))

        with open(output_filename, "w") as ofile:

            mnemonic_or_hex_seed = get_mnemonic(clargs.args)
            seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed)
            wallet = bip32_key_from_seed(seed, BIP32_VER_MAIN_PRIVATE, BIP32_FLAG_SKIP_HASH)

            signed_tx = build_bcash_transaction(args=clargs.args, wallet=wallet)

            # Set the pycoin netcode
            netcode = 'BTC'
            pycoin.networks.default.set_default_netcode(netcode)

            formatting.write_summary([signed_tx], sys.stdout)
            formatting.write_csv([signed_tx], ofile)

        return 0

    except exceptions.GARecoveryError as e:
        print(e)
        return -1

class ActiveSignatory:
    """Active signatory for which the keys are known, capable of signing arbitrary data"""

    def __init__(self, key):
        self.key = key

    def get_signature(self, sighash):
        sig = ec_sig_from_bytes(self.key, sighash, EC_FLAG_ECDSA)
        signature = ec_sig_to_der(sig) + bytearray([0x41, ]) # BCASH
        return signature

def build_bcash_transaction(args, wallet):
    ''' Builds up a single transaction to move all coins, subtracting out standard fees.'''

    # My BCH address on GDAX.
    destination_address = "17737DMBVoGbGvVZguWafAdq7T7AGcXraM"

    # https: // btc.com / e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70
    tx_hash_hex = "e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70"
    # Second output of last pre-fork transaction (index 1) held my balance.
    tx_out_index = 1
    # My pre-fork balance on the UTXO was 18232197
    satoshis = 18232197

    # Based on existing recovery tools, and decoding my own nlocktimes.zip, appears this should be the full hex string
    # specified in the "Input Strings" section on the block explorer for the pre-fork transaction.
    # https://btc.com/e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70
    tx_in_script_hex = "00473044022038761bb980bbe51d6d5b20fd7c8432a32df2205cd5d6ecd55561cfbecde28ada0220139d379bba850b777ad6d39b8f81720ce03fc5bc10c376dc9532a1086bdebb9b0147304402203cd7cd4fb805839d2305be4cea907ac62ba840c30282c685b5e6f124911e32a302204d9122cadad9955ef3429ef2fbc1f65196e4acfe1c501e9882000ccd09f5424e0147522102c145eea3b444a8d24219091f22b80ed019d31eea3decfd0511519e229ea82c8e2103df687ead9a104a5ab4e13a9306b9b302df31b52f54de793e1f43587f7ce25ff152ae"

    # ga_address_pointer.
    # Presumably, this is GreenAddress's internal 'pointer' to the wallet address in which the BTC/BCH was held at
    # the time of the fork. Two interpretations / ways to get this that seem irreconcilable.
    #
    # Existing recovery tools seem to pull this from prev_pointers in the nlocktimes.zip.
    # My nlocktimes from the subsequent transaction said '3', so I assume for this one it should be '2'.
    #
    # Other options is to pull it from the GA address book, finding the one corresponding to the address holding the
    # money at the time, which in my case is 3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA.
    # If I do that (see logs), I get entries with pointers from 20 down to 11. Relevant examples:
    # WARNING:root:ga_address: {u'pointer': 16, u'addr_type': u'p2sh', u'num_tx': 2, u'ad': u'3QpLKEeeAFiiErXH5mpY2MmfvFadr59HjG'}
    # WARNING:root:ga_address: {u'pointer': 15, u'addr_type': u'p2sh', u'num_tx': 2, u'ad': u'3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA'}
    # WARNING:root:ga_address: {u'pointer': 14, u'addr_type': u'p2sh', u'num_tx': 2, u'ad': u'3DorGeNFSC53DwV7XEUtSxgQb9HwzWNXo5'}
    #
    # Using this approach, I'd get '15'.
    ga_addresses = args.conn.call("addressbook.get_my_addresses")
    for ga_address in ga_addresses:
        logging.warning("ga_address: %s", ga_address)
    ga_address_pointer = 2

    # Find the last pre-fork transaction on btc.com, e.g.
    # https://btc.com/e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70
    #
    # Paste the "rawtx" (see link) into https://blockchain.info/decode-tx
    #
    # Pull tx_hash_hex from the "hash" field
    #
    # Find the entry under "out" that matches the part of the BTC that came back to you
    # (hint: value should match satoshis).
    spendable = Spendable.from_dict({
        "coin_value": satoshis,
        "script_hex": tx_in_script_hex,
        "tx_hash_hex": tx_hash_hex,
        "tx_out_index": tx_out_index
    })

    tx_out_script = pycoin.ui.script_obj_from_address(destination_address).script()
    tx_out = TxOut(satoshis, tx_out_script)
    tx = Tx(version=1, txs_in=[spendable.tx_in()], txs_out=[tx_out])
    logging.warning("pre-distrib raw unsigned tx: " + tx.as_hex())

    pycoin.tx.tx_utils.distribute_from_split_pool(tx, 'standard') # Subtract out standard fees
    logging.warning("raw unsigned tx: " + tx.as_hex())

    # SIGNING

    # User Signature
    tx_in_script = hex_to_bytes(tx_in_script_hex)
    tx_in_sighash = tx_segwit_hash(tx, 0, tx_in_script, satoshis)

    private_key = bip32_key_from_parent_path(wallet, [1, ga_address_pointer], BIP32_FLAG_SKIP_HASH)
    user_signatory = ActiveSignatory(bip32_key_get_priv_key(private_key))
    user_signature = user_signatory.get_signature(tx_in_sighash)

    tx.txs_in[0].script = inscript.multisig_2_of_2(tx_in_script, user_signature)
    logging.warning("tx with user signature only: " + tx.as_hex())

    # GreenAddress Signature
    h = hex_from_bytes(sha256d(tx.as_bin()))
    logging.warning("tx to sign:" + tx.as_hex())
    logging.warning("sha256d: " + h)

    twofactor = {}

    if args.twofactor["sms"]:
        args.conn.call("twofactor.request_sms", "sign_alt_tx",
                       {"txtype": "bcash", "sha256d": h})
        twofactor = {"method": "sms"}
    elif args.twofactor["email"]:
        args.conn.call("twofactor.request_email", "sign_alt_tx",
                       {"txtype": "bcash", "sha256d": h})
        twofactor = {"method": "email"}
    elif args.twofactor["any"]:
        logging.warning("need email/sms twofactor")
        assert False, "need email/sms twofactor"

    if args.twofactor["any"]:
        twofactor["code"] = user_input(twofactor["method"] + " code:")

    vault_sign_inputs = [{
        "value": satoshis,
        "script": tx_in_script_hex,
        "subaccount": None,
        "pointer": ga_address_pointer,
    }]
    ga_signatures = args.conn.call("vault.sign_alt_tx", tx.as_hex(), "bcash", vault_sign_inputs, twofactor)
    signatures = [hex_to_bytes(ga_signatures['signatures'][0]), user_signature]
    tx.txs_in[0].script = inscript.multisig(tx_in_script, signatures)
    logging.warning("fully signed tx: " + tx.as_hex())

    return tx
