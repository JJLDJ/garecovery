#  Recover Bitcoin Cash/BCASH/BCC/BCH from GreenAddress wallet for a single UTXO

WARNING: This is not necessarily functioning properly yet, and STILL HAS MY ADDRESS HARDCODED. Do not use as-is.

This is a stripped-down version of dumpyourbcash's Bitcoin Cash garecovery fork.
This version as-is works only for simple, typical wallets (2of2, no subaccounts, etc.).

This version also works on a single UTXO (unspent transaction). There is no dependence on any nlocktimes files -
everything you need to use it can be obtained from the combination of a block explorer (like btc.com) and your
GreenAddress account.

The tool expects you to specify the following parameters. The parameters are currently hardcoded in recoverycli.py, but
will be moved to flags once I've confirmed everything is working properly (i.e. once I actually get my own BCC out).
See recoverycli.py for more details about each value:
* destination_address (address to which funds are to be sent)
* tx_hash_hex (hash of the target UTXO -- the last pre-fork transaction)
* tx_out_index (index of address containing your balance in target UTXO)
* satoshis (your exact pre-fork BTC/BCC balance in the UTXO)
* tx_in_script_hex (full input script, specified in "Input Strings" section on btc.com, of the target UTXO)
* ga_address_pointer (pointer to the address in GreenAddress, still not entirely clear on this, but seems to be the index (1-based) of the transaction in your GreenAddress history)

Process:
* update variables at beginning of build_cash_transaction method in recoverycli.py
* cd garecovery-master
* virtualenv venv
* source venv/bin/activate
* pip install --require-hashes -r tools/requirements.txt
* pip install .
* garecovery-cli 2of2 -o garecovery.csv
* paste raw transaction (last field in garecovery.csv) into https://cashexplorer.bitcoin.com/tx/send

Issues:
* currently, when I follow these directions, using the data in my current recoverycli.py, I get the following error:
  "An error occured: 16: mandatory-script-verify-flag-failed (Script evaluated without error but finished with a
  false/empty top stack element). Code:-26"
