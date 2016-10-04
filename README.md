# xmr.llcoins.net
XMR Tools Site Files

A .zip file is provided of the generator page for convenient offline use. To verify the .asc, with gpg installed:

1. Get my key here: https://raw.githubusercontent.com/monero-project/monero/master/utils/gpg_keys/luigi1111.asc
2. Save it as **luigi1111.asc** and import it at the command line with `gpg --import luigi1111.asc`
3. In the directory where "addressgen.zip" and "addressgen.zip.asc" are located, type:

`gpg --verify addressgen.zip.asc addressgen.zip`

You should get `gpg: Good signature from "luigi1111 <luigi1111w@gmail.com>"`; you can ingore the warning about the key not being certified.
