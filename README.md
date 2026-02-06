# bitcoin-keys-generator

This project aims to create a script in python for generating bitcoin wallet address.

> [!CAUTION]
> For learning purpose only, do not use it for real, you may lose your bitcoins


Supported format :

- Native SegWit (Bech32) (address start by `bc1q` or `tb1q`)

Send a transaction on the sigtest network:

```bash
curl -X POST https://mempool.space/testnet4/api/tx -d ""
```