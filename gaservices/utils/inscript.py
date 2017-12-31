""" Utilities for generating input scripts, aka scriptSig/unlocking scripts """
from gaservices.utils.btc_ import gen_pushdata
from wallycore import hex_to_bytes, sha256


def _b(h):
    return hex_to_bytes(h)


def _push(d):
    return bytearray(gen_pushdata(d))


def p2pkh(pubkey_bin, signature_bin):
    return _push(signature_bin) + _push(pubkey_bin)

def multisig(redeem_script, signatures):
    '''Apply signatures to the redeem script, to form the signature script (ScriptSig).

    Signature order matters, and must match the order of the pubkey hashes in redeem script, which is hashed to form
    the PubkeyScript (output script).
    '''

    # Standard OP_0 byte that needs to always be present at beginning of P2SH multisigs, due to Bitcoin off-by-one
    # error. See https://bitcoin.org/en/developer-guide#multisig
    multisig = bytearray(_b('00'))

    for signature in signatures:
        multisig += _push(signature)
    return multisig + _push(redeem_script)

def prep_for_vault_sign_alt_tx(redeem_script, user_signature):

    # Standard OP_0 byte that needs to always be present at beginning of P2SH multisigs, due to Bitcoin off-by-one
    # error. See https://bitcoin.org/en/developer-guide#multisig
    multisig = bytearray(_b('00'))

    # GreenAddress placeholder. See https://api.greenaddress.it/vault.html#sign_alt_tx
    multisig += bytearray(_b('0100'))

    # Note that if we want to use the script returned by GA, we probably need to care about whether the user_sig or
    # the GA placeholder comes first.
    multisig += _push(user_signature)
    return multisig + _push(redeem_script)
