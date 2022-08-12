[![codecov](https://codecov.io/gh/hyperledger/firefly-btcconnect/branch/main/graph/badge.svg?token=OEI8A08P0R)](https://codecov.io/gh/hyperledger/firefly-btcconnect)
[![Go Reference](https://pkg.go.dev/badge/github.com/hyperledger/firefly-btcconnect.svg)](https://pkg.go.dev/github.com/hyperledger/firefly-btcconnect)

# Hyperledger FireFly Bitcoin Connector

This repo provides a reference implementation of the FireFly Connector API (FFCAPI)
for the Bitcoin blockchain.

See the [Hyperledger Firefly Documentation](https://hyperledger.github.io/firefly/overview/public_vs_permissioned.html#firefly-architecture-for-public-chains)
and the [FireFly Transaction Manager](https://github.com/hyperledger/firefly-transaction-manager) repository for
more information.

# License

Apache 2.0

## ABI Encoding

A key responsibility of the FFCAPI connector is to map from developer friendly JSON inputs/outputs
down to the binary encoding of the blockchain.

## Configuration

For a full list of configuration options see [config.md](./config.md)

## Example configuration

```yaml
connectors:
  - type: bitcoin
    server:
      port: 5103
    bitcoin:
      url: http://localhost:8332
```

## Launch btcd

```
./btcd -C ~/.btcd/btcd.conf --datadir ~/.btcd/testnet
```

## Launch btcwallet

````
 curl --user myuser -d '{"jsonrpc": "1.0", "id": "curltest", "method": "getblockchaininfo", "params": []}' -H 'content-type: application/json;' --cacert ~/.btcwallet/testnet/rpc.cert https://127.0.0.1:8332/ | jq```
````
