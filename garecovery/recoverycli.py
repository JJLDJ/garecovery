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


def main(argv=None):
    clargs.set_args(argv or sys.argv)
    logging.basicConfig(level=clargs.args.loglevel)

    try:
        mnemonic_or_hex_seed = get_mnemonic(clargs.args)
        seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed)
        wallet_key = bip32_key_from_seed(seed, BIP32_VER_MAIN_PRIVATE, BIP32_FLAG_SKIP_HASH)

        ga_address_pointer = lookup_ga_address_pointer(target_address=clargs.args.utxo_address)
        if ga_address_pointer is None:
            raise TypeError("Could not find internal GA pointer for address " + clargs.args.utxo_address)

        signed_tx = build_single_utxo_signed_bch_tx(
            args=clargs.args,
            wallet_key=wallet_key,
            destination_address=clargs.args.destination_address,
            ga_address_pointer=ga_address_pointer,
            redeem_script_hex=clargs.args.redeem_script_hex,
            tx_hash_hex=clargs.args.tx_hash_hex,
            utxo_index=clargs.args.utxo_index,
            incoming_satoshis=clargs.args.incoming_satoshis,
            total_fee_satoshis=clargs.args.total_fee_satoshis)

        # Set the pycoin netcode
        netcode = 'BTC'
        pycoin.networks.default.set_default_netcode(netcode)

        formatting.write_summary([signed_tx], sys.stdout)

        print("\nRaw transaction hex, to be pasted into a broadcast tool like https://cashexplorer.bitcoin.com/tx/send ...\n")
        print(signed_tx.as_hex())
        print("\n")

        return 0

    except exceptions.GARecoveryError as e:
        print(e)
        return -1

def build_single_utxo_signed_bch_tx(args, wallet_key, destination_address, ga_address_pointer, redeem_script_hex, tx_hash_hex, utxo_index, incoming_satoshis, total_fee_satoshis):
    '''Builds and signs a single-output Bitcoin Cash (BCH) transaction for a single UTXO.

    This method prepares a transaction that sends all BCH from a single UTXO (unspent transaction output) held by a
    2of2 GreenAddress multisig wallet to a single destination address (minus fees). If you have multiple UTXOs in your
    GreenAddress wallet (e.g. from multiple deposits to the wallet) you'll need to run the method once for each UTXO
    and broadcast each resulting TX separately.

    Very briefly, a UTXO represents some BTC (or BCH) that is currently held by the wallet. The UTXO is defined by the
    hash of the transaction that created it (tx_hash_hex) and the index of the output in the list of outputs for that
    transaction (utxo_index). If you're not clear on what "outputs" or UTXOs are, please spend a couple minutes
    familiarizing yourself with Bitcoin/BCH transaction basics, https://bitcoin.org/en/developer-guide#transactions or
    other references below, before trying to manually craft these parameters. I've documented them below, but some
    broader context is going to be helpful.

    This method is primarily intended for helping recover BCH associated with BTC you had in your GreenAddress wallet at
    the time of the August 1, 2017 hard fork that created BCH, but should also be usable if you accidentally sent BCH
    (instead of BTC) to a GreenAddress address post-fork.

    This method currently does not support:
        * 2of3 wallets
        * GreenAddress subaccounts
    Support for either of these should be manageable to add, so please contact me if it would be useful for you.

    References:
        P2SH multisigs: https://bitcoin.org/en/developer-guide#multisig
        OP_CHECKMULTISIG details: https://bitcoin.org/en/developer-reference#term-op-checkmultisig
        Opcodes: https://en.bitcoin.it/wiki/Script#Opcodes
        Detailed multisig TX breakdown (great if you want to parse through your TX or signature script):
            http://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/
        Decode a transaction (does not break down the scripts): https://blockchain.info/decode-tx
        Glossary entries:
            https://bitcoin.org/en/developer-guide#transactions
            https://bitcoin.org/en/glossary/address
            https://bitcoin.org/en/glossary/signature-script
            https://bitcoin.org/en/glossary/pubkey-script
            https://bitcoin.org/en/glossary/public-key
            https://bitcoin.org/en/glossary/output
            https://bitcoin.org/en/glossary/unspent-transaction-output
        My pre-fork and post-fork transactions from which I'm pulling my examples:
            Pre:    https://btc.com/e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70
            Post:   https://btc.com/a922ab0a66e66afe2ddb3141d88f8304e79c134e0bce8178823658b88b0e2b7a

    Args:
        args: Command-line args.

        wallet_key (int):
            GreenAddress wallet key, as returned by bip32_key_from_seed in
            https://github.com/ElementsProject/libwally-core/blob/master/include/wally_bip32.h

        destination_address (string):
            Standard-format BCH address to which you want to send the recovered BCH.
            Example: 19JRdfanvKzU7d6KvKgGTYar6kzBDba6Jn (author's BCH address -- use your own)
            These are generally base58check-encoded hashes. See https://bitcoin.org/en/glossary/address

        ga_address_pointer (int):
            GreenAddress's internal pointer to the address used by the UTXO (not destination address). This number let's
            GreenAddress know which keys to use when signing the transaction. You can find this by looking at the output
            of calls to GreenAddress's addressbook.get_my_addresses API method, and finding the entry that matches your
            UTXO's address. Other recovery tools pull this from the 'prev_pointers' field in nlocktimes.zip.

            Example:
                In my case, GreenAddress returned the following record (among others) when I called get_my_addresses.
                ga_address: {u'pointer': 15, u'addr_type': u'p2sh', u'num_tx': 2, u'ad': u'3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA'}
                Since 3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA was the address holding my UTXO, I'd set ga_address_pointer = 15.

        redeem_script_hex (string):
            Hex string encoding of the full redeem script for the UTXO (unspent transaction) you're trying
            to spend. Since we're extracting from a 2of2 P2SH multisig wallet (GreenAddress default), this
            string should start with '52' (the OP_2 opcode that represents the first '2' in '2of2'), and end with
            '52ae' (the OP_2 opcode that represents the second '2' in '2of2' and the OP_CHECKMULTISIG opcode).
            The middle contains the two Pubkeys for which signatures are needed in order to spend the UTXO.
            The string should be roughly 142 hex characters long, but could potentially vary a bit if GreenAddress
            employs pubkeys of different lengths.

            The redeem script will form the tail of the input script in the final transaction, and will be exactly the
            same for the BCH transaction as for the BTC transaction. The rest of the signature script will differ, since
            the signatures depend on other pieces of the transaction as well.

            The redeem script for a UTXO is generally not public. There are roughly three ways to get it in our case:
                1)  Extract it from the Input Script used by a BTC transaction that spent your UTXO (BTC, not BCH. As
                    noted, it starts with '52' and ends with '52ae', and is probably just the last 142 hex characters
                    of the input script. If you use the advanced view on the blockchain.info viewer, this will be the
                    last long string under the relevant ScriptSig. See this example link, which matches up with the
                    example redeemscript hex given below.
                    https://blockchain.info/tx/e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70?show_adv=true
                2)  Extract it from the nlocktimes.zip generated when you initiated the transaction holding the UTXO.
                    For recovery, this would be your last pre-fork nlocktimes.zip, though if you already have it, you
                    may want to instead just use one of the recovery tools that depends on nlocktimes.zip, such as
                    https://github.com/dumpyourbcash/garecovery
                3)  Figure out which pointer GreenAddress is supposed to use next, and determine both public keys from
                    that. I haven't done this, but it shouldn't be necessary in any case. If the pre-fork BTC funds
                    have already been spent, you can do (1). If they haven't, you can do (2), since GreenAddress lets
                    you re-request the "latest" nlocktimes through the wallet.

            Example: 5221036a08f0f8a665da604b3b4e1330ac7172e1e5a9a3466c95fc79bb50fe39eba8a22103649737c9a453eb7efa99c106117614c90ca96211542fea013ae5fda8d913bbb252ae

        tx_hash_hex (string):
            Hex string encoding of the transaction hash for the transaction containing the UTXO you're trying to spend.
            Example: e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70

        utxo_index (int):
            Index (0-based) of the unspent transaction output in the list of outputs in the transaction you're trying to
            spend.

            Example: My pre-fork transaction had two outputs, in order:
                0: 24870700 satoshis to 12HdJmPZPNo6hyYa224aUPPw1j7fhruemZ (address of person I was paying)
                1: 18232197 satoshis to 3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA (new multisig address where GA put my balance)
            Since my leftovers address was second, I'd set utxo_index = 1. Had it been first, I'd set utxo_index = 0.

        incoming_satoshis (int):
            Number of satoshis (BCH * 10^8) you want to spend from the UTXO. This should generally be the full amount in
            the UTXO if it's less, you'll be implicitly giving all the leftovers to the miners as a fee.
            Example: 18232197 in my case (0.18 BCH)

        total_fee_satoshis (int):
            The total number of satoshis you want to pay to the miners as a fee. Divide total_fee_satoshis by size of
            transaction (~350 bytes) to get the fee in satoshis per byte.

            See current fees by looking at recent transactions or sites like https://bitcointicker.co/bccnetworkstats/,
            though beware the units may differ.

            I've set the default to 30000 (0.0003 BCH), which is unnecessarily high (~100 satoshis per byte), to be safe
            and to ensure the transaction get processed immediately, and because it's what I used.

    Returns:
        pycoin.tx.Tx: The fully signed transaction object.

    '''

    # The UTXO you want to spend.
    spendable = Spendable.from_dict({
        "coin_value": incoming_satoshis,
        "script_hex": redeem_script_hex,
        "tx_hash_hex": tx_hash_hex,
        "tx_out_index": utxo_index
    })

    tx = pycoin.tx.tx_utils.create_tx(spendables=[spendable], payables=[destination_address], fee=total_fee_satoshis)
    logging.info("raw unsigned tx: %s", tx.as_hex())

    # SIGNING

    # User Signature
    redeem_script = spendable.script

    # The sighash of the transaction, which is the thing that will be signed independently by the wallet and
    # GreenAddress (via their API call). The hash is independent of the TX input signature scripts, since those will
    # end up including the signatures themselves.
    tx_in_sighash = tx_segwit_hash(tx, 0, redeem_script, incoming_satoshis)

    # The user signature depends only on the private key (derived from the user's wallet mnemonic) and the sighash
    # (derived from the transaction).
    private_key = bip32_key_get_priv_key(bip32_key_from_parent_path(wallet_key, [1, ga_address_pointer], BIP32_FLAG_SKIP_HASH))
    user_signature = ec_sig_to_der(ec_sig_from_bytes(private_key, tx_in_sighash, EC_FLAG_ECDSA)) + bytearray([0x41, ])

    # Updating the script at this point would not be necessary, except that the GreenAddress API method has expectations
    # for what the input script should look like when it signs the transaction (likely because it wants to be able to
    # return an updated version of the script, which we ignore anyway). The GreenAddress signature itself will not
    # depend on the script set here, only on the redeem script, which is passed to the API method separately.
    # If this isn't done, the API method will fail with 'Invalid signature placeholder'.
    tx.txs_in[0].script = inscript.prep_for_vault_sign_alt_tx(redeem_script, user_signature)

    # GreenAddress Signature
    twofactor = request_twofactor_if_needed(tx)
    vault_sign_inputs = [{
        "value": incoming_satoshis,
        "script": redeem_script_hex,
        "subaccount": None, # This recovery tool currently does not support subaccounts.
        "pointer": ga_address_pointer,
    }]
    # GreenAddress needs the tx.as_hex so that it can compute the hash and return an updated input script along with
    # the signature, but we're only interested in the signature, since we're rebuilding the input script below anyway.
    ga_signatures = args.conn.call("vault.sign_alt_tx", tx.as_hex(), "bcash", vault_sign_inputs, twofactor)

    # Signature order matters, and is determined by the order of the pubkeys used when creating the redeem script, and
    # thus the hash that forms the pubkey script stored in the UTXO. Since we have the redeem script, we could check the
    # order that the pubkeys appear in the redeem script, and make sure the signatures (derived from the corresponding
    # private keys) appear in the same order. However, for now we're assuming that GreenAddress always puts their
    # signature first, which means it should appear first in the signatures list below.
    signatures = [hex_to_bytes(ga_signatures['signatures'][0]), user_signature]
    tx.txs_in[0].script = inscript.multisig(redeem_script, signatures)
    logging.warning("fully signed tx: " + tx.as_hex())

    return tx

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
        logging.info("login greenaddress")
        # TODO: Consider refactoring this to return the objects instead of throwing them into args as a side effect.
        args.conn, args.wallet, args.login_data = do_login(m)
        args.twofactor = args.conn.call('twofactor.get_config')

    return m

def request_twofactor_if_needed(tx):
    '''Requests a two-factor authentication code for the GreenAddress TX signing API call, if necessary.

    Picks from one of the following two-factor methods, if available, in order: SMS, Email
    Fails if two-factor is enabled, but is not one of the listed methods.

    Returns:
        Empty dict if two factor authentication is disabled.
        Otherwise, returns:
        {
            "method": two-factor authentication method used
            "code": two-factor authentication code provided by user
        }
    '''

    tx_bin_hash = hex_from_bytes(sha256d(tx.as_bin()))
    logging.info("tx to be sent to GreenAddress: " + tx.as_hex())
    logging.info("tx hash (sha256d): " + tx_bin_hash)

    if not clargs.args.twofactor["any"]:
        return {}

    # TODO: Make this work for other (all?) two-factor methods.
    if clargs.args.twofactor["sms"]:
        return request_twofactor(tx_bin_hash, method="sms")
    if clargs.args.twofactor["email"]:
        return request_twofactor(tx_bin_hash, method="email")

    need_twofactor_string = "Please enable two-factor authentication for at least one of the methods: sms, email"
    logging.warning(need_twofactor_string)
    assert False, need_twofactor_string


def request_twofactor(tx_bin_hash, method):
    '''Requests a two-factor authentication code via specified method for the GA TX signing call.'''
    clargs.args.conn.call("twofactor.request_" + method, "sign_alt_tx", {"txtype": "bcash", "sha256d": tx_bin_hash})
    return {
        "method": method,
        "code": user_input(method + " code: ")
    }

def lookup_ga_address_pointer(target_address):
    '''Looks up the GreenAddress internal address pointer for a given address managed by the GreenAddress wallet.

    Args:
        target_address (string):
            Standard-format BTC/BCH address managed by GreenAddress (presumably the one that is currently holding your
            BCH). You can see these in the GreenAddress wallet GUI under Inputs/Outputs when you click on a transaction.
            Example: 3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA
            These are generally base58check-encoded hashes. See https://bitcoin.org/en/glossary/address

    Returns:
        ga_address_pointer (int): GreenAddress's internal pointer to the specified address. This number let's
            GreenAddress know which keys to use when signing the transaction. Returns None if no match was found.

    '''

    ga_address_pointer = None

    # Loop through all the addresses in the account, in descending order, in batches of 10 (batch size dictated by API).
    ga_page_min_pointer = 10000000
    while ga_page_min_pointer > 1:
        ga_addresses = clargs.args.conn.call("addressbook.get_my_addresses", 0, ga_page_min_pointer)
        for ga_address in ga_addresses:
            # Example ga_address: {'pointer': 15, 'addr_type': 'p2sh', 'num_tx': 2, 'ad': '3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA'}
            logging.info("ga_address: %s", ga_address)
            if ga_address['ad'] == target_address:
                ga_address_pointer = ga_address['pointer']
        ga_page_min_pointer = ga_addresses[-1]['pointer']

    return ga_address_pointer
