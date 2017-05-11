# xmr.llcoins.net
XMR Tools Site Files

**Pages:**

1. addressgen.html -- provides a streamlined account generator, including three different methods of encryption
2. addresstests.html -- provides an extensive amount of options for step-by-step private/public key/address generation and verification for several Cryptonote coins
3. checktx.html -- allows for the decoding of one-time-output keys of a particular transaction, associating them with their public account. This requires secret data (either the view private key, or the transaction private key) and an internet connection to MoneroBlocks to get the transaction data.
4. sign.html -- generates and verifies signatures on arbitrary data using one of your account private keys (spend key or view key)
5. slowhash.html -- generates the CryptoNight hash of hexadecimal input data; overall not too useful except for visually checking a block's PoW result

A .zip file is provided of the site for convenient offline use (note: you must have an internet connection to use the checktx page). To verify the .asc, with gpg installed:

1. Get my key here: https://raw.githubusercontent.com/monero-project/monero/master/utils/gpg_keys/luigi1111.asc
2. Save it as **luigi1111.asc** and import it at the command line with `gpg --import luigi1111.asc`
3. In the directory where "site.zip" and "site.zip.asc" are located, type:

`gpg --verify site.zip.asc site.zip`

You should get `gpg: Good signature from "luigi1111 <luigi1111w@gmail.com>"`; you can ingore the warning about the key not being certified.
