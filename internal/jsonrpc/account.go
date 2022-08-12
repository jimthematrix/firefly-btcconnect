// Copyright © 2022 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jsonrpc

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (c *RPCClient) calculateBalance(confirms int32) (btcutil.Amount, error) {
	var balance btcutil.Amount
	err := walletdb.View(c.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		blk := c.Manager.SyncedTo()
		balance, err = c.TxStore.Balance(txmgrNs, confirms, blk.Height)
		return err
	})
	return balance, err
}

// Balances records total, spendable (by policy), and immature coinbase
// reward balance amounts.
type Balances struct {
	Total          btcutil.Amount
	Spendable      btcutil.Amount
	ImmatureReward btcutil.Amount
}

// CalculateAccountBalances sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
//
// This function is much slower than it needs to be since transactions outputs
// are not indexed by the accounts they credit to, and all unspent transaction
// outputs must be iterated.
func (c *RPCClient) calculateAccountBalances(account uint32, confirms int32) (Balances, error) {
	var bals Balances
	err := walletdb.View(c.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := c.Manager.SyncedTo()

		unspent, err := c.TxStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for i := range unspent {
			output := &unspent[i]

			var outputAcct uint32
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, c.chainParams)
			if err == nil && len(addrs) > 0 {
				_, outputAcct, err = c.Manager.AddrAccount(addrmgrNs, addrs[0])
			}
			if err != nil || outputAcct != account {
				continue
			}

			bals.Total += output.Amount
			if output.FromCoinBase && !confirmed(int32(c.chainParams.CoinbaseMaturity),
				output.Height, syncBlock.Height) {
				bals.ImmatureReward += output.Amount
			} else if confirmed(confirms, output.Height, syncBlock.Height) {
				bals.Spendable += output.Amount
			}
		}
		return nil
	})
	return bals, err
}

// AccountNumber returns the account number for an account name under a
// particular key scope.
func (c *RPCClient) accountNumber(scope waddrmgr.KeyScope, accountName string) (uint32, error) {
	manager, err := c.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	var account uint32
	err = walletdb.View(c.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		account, err = manager.LookupAccount(addrmgrNs, accountName)
		return err
	})
	return account, err
}

// confirmed checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func confirmed(minconf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minconf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}
