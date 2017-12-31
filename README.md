#  Recover BCH (aka Bitcoin Cash, BCC, BCASH) from GreenAddress wallet for a single UTXO

## Overview

What this guide is for:
* Lets you generate a transaction that will spend the BCH that forked from Bitcoin (BTC) that was in your 
  GreenAddress wallet at the time of the fork (August 1, 2017), **without** an nlocktimes.zip file.
* More generally, lets you manually craft a BCH transaction that sends BCH from a GreenAddress wallet address
  to any other BCH address you want. Thus, in principle, you could also use this tool to recover BCH that was
  accidentally sent to one of your GreenAddress wallet addresses post-fork. The guide doesn't cover this case
  currently. If you need it, please let me know.
* 2of2 GreenAddress wallets (wallets for which there are only two signatures - yours and GreenAddress's).
  Some GreenAddress wallets are 2of3 wallets (see below)


What this guide does not do:
* Does not scan your GreenAddress wallet looking for unspent BCH transactions. You have to do that part manually
  using a blockchain explorer, though instructions are in the walkthrough.
* Does not work well if you have not made a BTC transaction using the pre-fork BTC that was in your account. If that's
  your situation, either spend some of the BTC, or just re-generate your current nlocktimes.zip and use the
  dumpyourbcash recovery tool (see Background section below).
* Does not support 2of3 wallets, in which there's a third possible key, a backup you control (see 
  [GreenAddress faq](https://greenaddress.it/en/faq.html))
* Does not support wallets with subaccounts
* Does not work for moving BTC, only BCH

Adding support for 2of3 wallets and wallets with subaccounts should be feasible (the original dumpyourbcash tool
supports both). If you have a need, please let me know.

I'm not likely to add support for the wallet scanning, partly because I don't know how much effort it would take to
start with the wallet and go querying transactions on both blockchains to find what I'm looking for.


## Background

**tl;dr** Potentially interesting context -- feel free to skip if you're in a hurry to get on with the walkthrough.

On August 1, 2017, the Bitcoin blockhain was hard-forked, meaning that the chain split into two chains with slightly
different rules, effectively generating two currencies: the existing Bitcoin (BTC) and the new Bitcoin Cash (BCH or 
BCC). Anyone who had BTC at the time of the fork, in any wallet, owned the exact same amount of BCH. After the fork,
even if the BTC was spent, the BCH still remained in the wallet, since BCH and BTC use different hash functions so
that transactions on one blockchain fork can't simply be replayed on the other. 

Modifying a wallet UI to support BCH in addition to BTC takes some effort (both up-front and in maintenance),
so some wallets did not add support for working with the BCH. GreenAddress is one of those wallets that chose not to
add support for BCH (see their blog posts 
[here](https://blog.greenaddress.it/2017/07/24/uasf-segwit-softfork-enforcement/) and 
[here](https://blog.greenaddress.it/2017/03/27/greenaddress-position-on-contentious-forks/)).

Most BTC holders could get around the lack of UI support for BCH by manually building, signing, and broadcasting
their own BCH transaction, which would then move the BCH to another wallet that supported it. Unfortunately, with
wallets like GreenAddress which require multiple signatures (one from the user and one from GreenAddress), manually
signing a transaction is not so easy, since the user can't generate the GreenAddress signature. For BTC,
GreenAddress emails partially pre-signed transactions to the user after each transaction, via the nlocktimes.zip file.
That pre-signed transaction would let the user recover their full BTC balance, even if the GreenAddress service were
to shut down. However, those pre-signed transactions would not work directly for BCH, since they used the BTC hash
function (IIUC), so the BCH was stuck.

Fortunately, [in early September](https://blog.greenaddress.it/2017/09/06/segregated-witness-updates/), GreenAddress
partially relented, adding a [vault.sign_alt_tx method](https://api.greenaddress.it/vault.html#sign_alt_tx) to their API
that would allow a user to generate the GreenAddress signature for a BCH transaction. It then became possible to
move BCH out of the GreenAddress wallet.

Shortly thereafter, a GitHub user named dumpyourbcash created a fork of the GreenAddress BTC
recovery tool (garecovery), found [here]((https://github.com/dumpyourbcash/garecovery), that used the new API method
and worked for BCH transactions. This tool required the user to provide the last pre-fork nlocktimes.zip file provided
by GreenAddress, but the signatures in the file were not used - it was just a convenient place to get other information
needed to build the transactions.

Unfortunately, some users (like me), for whatever reason, had lost their last pre-fork nlocktimes.zip file, so could
not use the tool. GitHub user Mikadily recognized that the nlocktimes.zip itself was not actually needed, and produced
[another fork](https://github.com/Mikadily/garecovery) that let you build your own nlocktimes JSON file, specifying
all the necessary paremters manual, and consume it in lieu of nlocktimes.zip. This tool would have worked for me, but
I had trouble figuring out exactly what to fill in for each parameter, and updating the nlocktimes.json file was a
little clunky.

That brings us to this tool/guide. I've stripped down the dumpyourbcash code to a point where it was simple enough
for me to understand and figure out what I was doing wrong, converted the necessary parameters to flags or extracted
them automatically, and documented them. If you have the last pre-fork nlocktimes.zip file, the dumpyourbcash tool is
probably the way to go. If you have any other use case, this is probably the tool for you.


## Walkthrough for recovering BCH from BTC in wallet at time of fork

### 1) Get A Linux Machine

If you already have a Linux machine, you're probably good to go here.

If you're like me, and only run Windows at home, you have a bunch of options for getting access to a Linux terminal.
What was easiest for me was to spin up a simple Linux VM using Google Cloud Compute Engine. Once you start it up,
there's an SSH button next to the VM instance that lets you open a terminal in a browser window. You can do everything
you need by pasting commands in there.

You don't need anything fancy, just the minimal parameters as you'd see in the
[quick-start guide here](https://cloud.google.com/compute/docs/quickstart-linux),
except that I used an Ubuntu 17.04 image instead of the recommended Debian.
If you go this route, just don't forget to shut down / delete the instance once you're done, else you'll continue to
get charged.

### 2) Download Code and Perform Basic Python Setup

From whatever directory you care to be in on your Linux machine, run the following to download the tool from the
git repo, unzip it, ensure you have the appropriate packages installed, and switch to the appropriate directory.

```sh
wget https://github.com/JJLDJ/garecovery/archive/master.zip
sudo apt-get unzip
unzip master.zip
sudo apt-get update -qq
sudo apt-get install python{,3}-pip python{,3}-dev build-essential python{,3}-virtualenv -yqq
cd garecovery-master
```

From inside this directory, run the following to create a new Python virtual environment (venv) in which to install the
tool and its dependencies and execute the tool. If you need to make a change to the code or restart your session, I
recommend you `rm -rf venv`, then run all these commands again. Also note that if you're in the venv and want
to get out, use the command `deactivate`.

```sh
virtualenv venv
source venv/bin/activate
pip install --require-hashes -r tools/requirements.txt 
pip install .
```

### 3) Treasure Hunting: identify the parameters you need


When you run this tool, you're going to be preparing a transaction which, when broadcast, will send all BCH from a
single UTXO ([unspent transaction output](https://bitcoin.org/en/glossary/unspent-transaction-output)) held by your 2of2
GreenAddress multisig wallet, to a single destination BCH address (minus fees). If you have multiple UTXOs in your
GreenAddress wallet (e.g. from multiple deposits to the wallet) you'll need to run the tool once for each UTXO and
broadcast each resulting TX (transaction) separately.

Very briefly, a UTXO represents some BTC (or BCH) that is currently held by the wallet. The UTXO is defined by the
hash of the transaction that created it (tx_hash_hex) and the index of the output in the list of outputs for that
transaction (utxo_index). I've tried to make this part of the walkthrough fairly procedural, such that you can follow
the directions without fully understanding each of these parameters. However, if you get stuck or confused, or just 
want a better understanding of what's going on, please spend a couple minutes familiarizing yourself with
[Bitcoin/BCH transaction basics](https://bitcoin.org/en/developer-guide#transactions) before proceeding. I also have
the parameters extensively documented in the `build_single_utxo_signed_bch_tx` method of `garecovery/recoverycli.py`,
so please look there as well.  

#### What you'll need

Here are the flags you'll need to define for the tool, along with the values I used for my recovery as examples. All
these parameters will be specific to your transaction and will need to be changed. Most will fail if you don't update
them, but do **not** use the same destination-address, unless you want to send me all your BCH.
* `--destination-address 19JRdfanvKzU7d6KvKgGTYar6kzBDba6Jn`
  * This one is easy - it's just the standard-format BCH address to which you want to send your recovered BCH.
    Especially if you're sending to an exchange, make sure it's a BCH/BCC address and not a BTC address!
* `--incoming-satoshis 18232197`
  * Total number of satoshis (BCH * 10^8) in the UTXO that you want to spend (the full amount from the output, excluding
    fees. Should be the full amount in the UTXO.
* `--utxo-address 3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA`
  * Address managed by GreenAddress that is currently holding your BCH. Used to look up GreenAddress's internal pointer
    reference to the relevant private keys.
* `--utxo-index 1`
  * Index (0-based) of the unspent transaction output in the list of outputs in the transaction you're trying to spend.
* `--tx-hash-hex e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70`
  * Hex string encoding of the transaction hash for the transaction containing the UTXO you're trying to spend. The hash
    hex string is generally used as the transaction identifier, so will show up in the transaction's URL in blockchain
    explorers (e.g. [here](https://btc.com/e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70))
* `--redeem-script-hex 5221036a08f0f8a665da604b3b4e1330ac7172e1e5a9a3466c95fc79bb50fe39eba8a22103649737c9a453eb7efa99c106117614c90ca96211542fea013ae5fda8d913bbb252ae`
  * Hex string encoding of the full redeem script for the UTXO (unspent transaction) you're trying to spend. The redeem
    script determines what signatures are required in order to spend the UTXO. Should start with '52' and end with 'ae'.

#### Where to get it

Start with your GreenAddress transaction log in your wallet UI. Mine is pretty simple, since I only ever made one
deposit, and just kept making withdrawals, so I only had one UTXO at any given time, and in particular, only one at
the time of the fork. If you have lots of UTXOs, you'll need to do a little more digging to make sure you find them
all. I'm just walking through my simple example here, and you can generalize/repeat as needed.

![GreenAddress TX history UI](https://content.screencast.com/users/JJLDJ/folders/Jing/media/f81c2b50-6c25-4cbd-8065-9bfad0e871cf/2017-12-30_2252.png)

I'll start by clicking on my last pre-fork transaction, labeled 'To 12HdJmPZPNo6hyYa224aUPPw1j7fhruemZ'. It comes up
with these details:

![pre-fork TX](https://content.screencast.com/users/JJLDJ/folders/Jing/media/c2687368-5bf1-4403-9a55-7a196cb97e06/2017-12-30_2304.png)

You can see in the Outputs section that I paid 248mBTC to a recipient, and the balance of 182mBTC went back to my
wallet in a new address. In the post-fork TX, I spent that output as well, but only the BTC. On the BCH blockchain, it's
still unspent, so it's the UTXO we're looking for. From it, we can fill in a couple of our flags
* incoming-satoshis is just the balance (ignoring the decimal) that went back to my account, 18232197
* utxo-address is the new address holding my balance, 3FQBSLAsFF4NMuiEVShMae7Uu9JcVSRQvA
* utxo-index is determined by where the UTXO falls in the outputs list. Since it's second in the list, utxo-index is 1.
  If it were first it would be 0, third it would be 2, and so on. 
* tx-hash-hex is just the transaction Hash listed at the top of the UI

All that remains is `redeem-script-hex`. For that, we need to look at the post-fork TX in a (BTC) blockchain explorer.
To get to it, you can open the corresponding TX from the GreenAddress UI, or, just open the pre-fork TX in a blockchain
explorer ([like this](https://blockchain.info/tx/e65e67cef4078f0a44f46bd1740c21e3dc8577c90c71e49fea876cb7bf135b70)),
then follow the money -- click through to the utxo-address, and then to the TX that spent the incoming-satoshis
([like this](https://blockchain.info/tx/a922ab0a66e66afe2ddb3141d88f8304e79c134e0bce8178823658b88b0e2b7a)).

Make sure you're viewing the TX in a blockchain explorer that breaks down the Input Scripts (e.g. blockchain.info does,
btc.com does not). I'll assume you're using blockchain.info for now.

![post-fork TX in blockchain.info](https://content.screencast.com/users/JJLDJ/folders/Jing/media/92fca5e4-c8d0-474c-aaf9-7fdd9e78c09b/2017-12-30_2326.png)

(You may need to activate an "advanced" view to see the breakdown in the above screenshot.)

The redeem script hex will be the last long hex string under the Input Scripts section. For our multisig wallets, it
should always start with '52' and end with 'ae'.

If the transaction you're looking at has multiple inputs, there will be a different input script breakdown for each input.
The inputs (listed in the upper-left corner) and input scripts will be listed in the same order - make sure you're copying the redeem script from the
correct input (the one that has the matching utxo-address and incoming-satoshis amounts). 

### 4) Generate and broadcast your transaction

Once you have the values above, assemble them into a one-line command like the following and run it from the 
garecovery-master directory:

`garecovery-cli --destination-address XXXXXXXXXXXXXXXXXX --incoming-satoshis XXXXXXXX --utxo-address XXXXXXXXXXXXXXXXXXXXX --utxo-index X --tx-hash-hex XXXXXXXXXXXXXXXXXX --redeem-script-hex XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

If you'd like, you can also add a `--total-fee-satoshis XXXXXXXX` flag. I have the default set to 30000, which is a
little high. Someone else reported using 5000 without incident. It just depends on current fee rates.

The script will ask you for your mnemonic (the multi-word phrase that yields the private key to your wallet), which is
needed in order to generate your part of the signature.

It'll then ask you for your two-factor authentication code (if you have one). It'll currently try SMS first, then email,
then fail if neither of those is enabled. If you have two-factor enabled, but neither SMS nor email, please enable one
of them and then retry.

The script then prints out a summary of the transaction, followed by the raw transaction hex. For me, it looked like:

```
                                                           tx id lock time      total out                destination address     coin value
---------------------------------------------------------------- --------- -------------- ---------------------------------- --------------
07ba2356a9669fbf2fad833f705e370ad340d31edc1169412db1e4fed20b7b25         0 0.18202197 BCH 19JRdfanvKzU7d6KvKgGTYar6kzBDba6Jn 0.18202197 BCH

total value = 0.18202197 BCH in 1

Raw transaction hex, to be pasted into a broadcast tool like https://cashexplorer.bitcoin.com/tx/send ...

0100000001705b13bfb76c87ea9fe4710cc97785dce3210c74d16bf4440a8f07f4ce675ee601000000db0048304502210089b085bcb067ea966bfaa9aa45473d1f9cc69ebcbfa7167dcd58d184536bf12602200629a05a35900229a3fb16661ea851c0991ed22e0462cfca9d0155954f37f71a41483045022100b7afd14a68e44c80601ddc02e19d7c639b89d50217f37dcc4e56411141cd252102206f958518c4cbfca60ed0e1a903df8763673ce3297d7bbc1dfa7d227d6884c29c41475221036a08f0f8a665da604b3b4e1330ac7172e1e5a9a3466c95fc79bb50fe39eba8a22103649737c9a453eb7efa99c106117614c90ca96211542fea013ae5fda8d913bbb252aeffffffff0155be1501000000001976a9145b0ca3b7052ffdb2efe9175d44d1b8eae57e524a88ac00000000
```

You can then paste the raw TX hex into one of these BCH broadcast tools, which will send it out to be picked up by the
miners. I personally prefer the cashexplorer.bitcoin.com tool, since it gave me slightly more useful responses:
* https://cashexplorer.bitcoin.com/tx/send
* https://pool.viabtc.com/tools/BCH/broadcast/


If you want to verify that the transaction looks good before broadcasting it (e.g. that it's really sending to your
address), paste it into a [decoder tool](https://blockchain.info/decode-tx).

After you've broadcast, plus some delay, you should be able to see your new transaction in a BCH block explorer (e.g.
[mine is here](https://bch.btc.com/07ba2356a9669fbf2fad833f705e370ad340d31edc1169412db1e4fed20b7b25)). 

If you get an error like `An error occured: 16: mandatory-script-verify-flag-failed`, please double-check your inputs.
Note that when I try to re-broadcast an existing transaction (e.g. mine above), I get a misleading error `Missing 
inputs. Code:-25`.

## Walkthrough for recovering BCH sent to a GreenAddress wallet post-fork

This is not fleshed out, since I haven't tried it yet. However, the process would be the same as for recovering fork
BCH, with the exceptions that:

The 'pre-fork' transaction is instead the transaction via which you sent BCH to a GreenAddress address. It will
not be visible in the GreenAddress UI, so you'll need to look it up in one of the blockchain explorers to get the
four parameters you previously pulled from the GreenAddress UI for the pre-fork transaction (utxo-address will be the
address to which you sent the BCH, etc.).

The 'post-fork' equivalent transaction as such won't exist, but we still need a redeem script. Fortunately, the redeem
script depends only on the address to which you sent the BCH, not on the amount you spent or the transaction you spent
it from. Thus, the first thing to do would be to check blockchain.info to see if there are any transactions that have
spent from the same address (the utxo-address). If so, you can pull the redeem script from one of those. If not, you 
could (probably) force GreenAddress to generate such a transaction by sending a small amount of BTC to the same address,
then spending it using the GreenAddress wallet UI. I'm not sure how easy it would be to force GreenAddress to spend a
particular output without spending *all* the BTC from your wallet though.

It should be possible to modify the tool to generate the redeem script directly from the addresses (we just need the
public keys, and can verify what we come up with and compare to the address itself), which would simplify both recovery
use cases, but it's some added development work. If the above isn't working for you, and you think such a modification
would help your use case, please let me know.

## Help

All the command-line flags used to run this tool (the `garecovery-cli` flags) are essentially public information, so you
can freely post them, with the caveat that it will associate you (whatever user you're posting with) with those BCH/BTC
addresses / transactions. The mnemonic and two-factor code are **not** public and should **never** be given out.

If you're having trouble getting your transaction to validate, and need help, post the command-line invocation if you're
comfortable revealing which transaction is yours, or PM me with it, and I'll see if I can help (though expect my
turnaround time to be on the order of a couple days).

If for any reason you feel inclined to give me a gift, my BCH address is `19JRdfanvKzU7d6KvKgGTYar6kzBDba6Jn`.
Thanks for reading!

## Kudos

Shout-out to those who wrote tools / guides on which I depended heavily or took some key inspirations:
* https://github.com/dumpyourbcash/garecovery
* https://github.com/Mikadily/garecovery
* https://www.reddit.com/r/greenaddress/comments/7ibz8t/steps_to_move_2of2_with_ntimelockzip/
* http://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/