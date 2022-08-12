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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/hyperledger/firefly-common/pkg/log"
)

var (
	waddrmgrNamespaceKey = []byte("waddrmgr")
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

func (c *RPCClient) handleChainNotifications() {
	defer c.wg.Done()

	l := log.L(c.ctx)
	for {
		select {
		case n, ok := <-c.Notifications():
			if !ok {
				return
			}
			l.Tracef("Read from chain notifications channel: %+v\n", n)

			var notificationName string
			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				l.Info("Client connected")
			case chain.BlockConnected:
				l.Info("Block connected")
				notificationName = "block connected"
			case chain.BlockDisconnected:
				l.Info("Block disconnected")
				notificationName = "block disconnected"
			case chain.RelevantTx:
				l.Infof("Received relevant tx %+v\n", n)
				err = walletdb.Update(c.db, func(tx walletdb.ReadWriteTx) error {
					return c.addRelevantTx(tx, n.TxRecord, n.Block)
				})
				notificationName = "relevant transaction"
			case chain.FilteredBlockConnected:
				// Atomically update for the whole block.
				if len(n.RelevantTxs) > 0 {
					err = walletdb.Update(c.db, func(
						tx walletdb.ReadWriteTx) error {
						var err error
						for _, rec := range n.RelevantTxs {
							err = c.addRelevantTx(tx, rec,
								n.Block)
							if err != nil {
								return err
							}
						}
						return nil
					})
				}
				notificationName = "filtered block connected"

			// The following require some database maintenance, but also
			// need to be reported to the wallet's rescan goroutine.
			case *chain.RescanProgress:
				err = c.catchUpHashes(n.Height)
				notificationName = "rescan progress"
				select {
				case c.rescanNotifications <- n:
				case <-c.quitChan():
					return
				}
			case *chain.RescanFinished:
				err = c.catchUpHashes(n.Height)
				notificationName = "rescan finished"
				c.SetChainSynced(true)
				select {
				case c.rescanNotifications <- n:
				case <-c.quitChan():
					return
				}
			}
			if err != nil {
				// If we received a block connected notification
				// while rescanning, then we can ignore logging
				// the error as we'll properly catch up once we
				// process the RescanFinished notification.
				if notificationName == "block connected" &&
					waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) && !c.ChainSynced() {

					l.Debugf("Received block connected notification for height %v while rescanning",
						n.(chain.BlockConnected).Height)
					continue
				}

				l.Errorf("Unable to process chain backend %v notification: %v", notificationName,
					err)
			}
		case <-c.quit:
			return
		}
	}
}

// handleNotification examines the passed notification type, performs
// conversions to get the raw notification types into higher level types and
// delivers the notification to the appropriate On<X> handler registered with
// the client.
func (c *RPCClient) handleNotification(ntfn *rawNotification) {
	l := log.L(c.ctx)

	switch ntfn.Method {
	// OnBlockConnected
	case btcjson.BlockConnectedNtfnMethod:
		blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.Params)
		if err != nil {
			l.Warnf("Received invalid block connected "+
				"notification: %v", err)
			return
		}

		c.onBlockConnected(blockHash, blockHeight, blockTime)

	// OnBlockDisconnected
	case btcjson.BlockDisconnectedNtfnMethod:
		blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.Params)
		if err != nil {
			l.Warnf("Received invalid block connected "+
				"notification: %v", err)
			return
		}

		c.onBlockDisconnected(blockHash, blockHeight, blockTime)

	// OnRecvTx
	case btcjson.RecvTxNtfnMethod:
		tx, block, err := parseChainTxNtfnParams(ntfn.Params)
		if err != nil {
			l.Warnf("Received invalid recvtx notification: %v",
				err)
			return
		}

		c.onRecvTx(tx, block)

	// OnRedeemingTx
	case btcjson.RedeemingTxNtfnMethod:
		tx, block, err := parseChainTxNtfnParams(ntfn.Params)
		if err != nil {
			l.Warnf("Received invalid redeemingtx "+
				"notification: %v", err)
			return
		}

		c.onRedeemingTx(tx, block)

	// OnRescanFinished
	case btcjson.RescanFinishedNtfnMethod:
		hash, height, blkTime, err := parseRescanProgressParams(ntfn.Params)
		if err != nil {
			l.Warnf("Received invalid rescanfinished "+
				"notification: %v", err)
			return
		}

		c.onRescanFinished(hash, height, blkTime)

	// OnRescanProgress
	case btcjson.RescanProgressNtfnMethod:
		hash, height, blkTime, err := parseRescanProgressParams(ntfn.Params)
		if err != nil {
			l.Warnf("Received invalid rescanprogress "+
				"notification: %v", err)
			return
		}

		c.onRescanProgress(hash, height, blkTime)

	// OnUnknownNotification
	default:
		l.Warnf("Unknown notification %s\n", ntfn.Method)
	}
}

// wrongNumParams is an error type describing an unparseable JSON-RPC
// notificiation due to an incorrect number of parameters for the
// expected notification type.  The value is the number of parameters
// of the invalid notification.
type wrongNumParams int

// Error satisifies the builtin error interface.
func (e wrongNumParams) Error() string {
	return fmt.Sprintf("wrong number of parameters (%d)", e)
}

// parseChainNtfnParams parses out the block hash and height from the parameters
// of blockconnected and blockdisconnected notifications.
func parseChainNtfnParams(params []json.RawMessage) (*chainhash.Hash,
	int32, time.Time, error) {

	if len(params) != 3 {
		return nil, 0, time.Time{}, wrongNumParams(len(params))
	}

	// Unmarshal first parameter as a string.
	var blockHashStr string
	err := json.Unmarshal(params[0], &blockHashStr)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	// Unmarshal second parameter as an integer.
	var blockHeight int32
	err = json.Unmarshal(params[1], &blockHeight)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	// Unmarshal third parameter as unix time.
	var blockTimeUnix int64
	err = json.Unmarshal(params[2], &blockTimeUnix)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	// Create hash from block hash string.
	blockHash, err := chainhash.NewHashFromStr(blockHashStr)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	// Create time.Time from unix time.
	blockTime := time.Unix(blockTimeUnix, 0)

	return blockHash, blockHeight, blockTime, nil
}

func parseHexParam(param json.RawMessage) ([]byte, error) {
	var s string
	err := json.Unmarshal(param, &s)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(s)
}

// parseChainTxNtfnParams parses out the transaction and optional details about
// the block it's mined in from the parameters of recvtx and redeemingtx
// notifications.
func parseChainTxNtfnParams(params []json.RawMessage) (*btcutil.Tx,
	*btcjson.BlockDetails, error) {

	if len(params) == 0 || len(params) > 2 {
		return nil, nil, wrongNumParams(len(params))
	}

	// Unmarshal first parameter as a string.
	var txHex string
	err := json.Unmarshal(params[0], &txHex)
	if err != nil {
		return nil, nil, err
	}

	// If present, unmarshal second optional parameter as the block details
	// JSON object.
	var block *btcjson.BlockDetails
	if len(params) > 1 {
		err = json.Unmarshal(params[1], &block)
		if err != nil {
			return nil, nil, err
		}
	}

	// Hex decode and deserialize the transaction.
	serializedTx, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, nil, err
	}
	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, nil, err
	}

	// TODO: Change recvtx and redeemingtx callback signatures to use
	// nicer types for details about the block (block hash as a
	// chainhash.Hash, block time as a time.Time, etc.).
	return btcutil.NewTx(&msgTx), block, nil
}

// parseRescanProgressParams parses out the height of the last rescanned block
// from the parameters of rescanfinished and rescanprogress notifications.
func parseRescanProgressParams(params []json.RawMessage) (*chainhash.Hash, int32, time.Time, error) {
	if len(params) != 3 {
		return nil, 0, time.Time{}, wrongNumParams(len(params))
	}

	// Unmarshal first parameter as an string.
	var hashStr string
	err := json.Unmarshal(params[0], &hashStr)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	// Unmarshal second parameter as an integer.
	var height int32
	err = json.Unmarshal(params[1], &height)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	// Unmarshal third parameter as an integer.
	var blkTime int64
	err = json.Unmarshal(params[2], &blkTime)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	// Decode string encoding of block hash.
	hash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		return nil, 0, time.Time{}, err
	}

	return hash, height, time.Unix(blkTime, 0), nil
}

func (c *RPCClient) onBlockConnected(hash *chainhash.Hash, height int32, time time.Time) {
	log.L(c.ctx).Tracef("onBlockConnected [hash: %s, height: %d]", hash.String(), height)
	select {
	case c.enqueueNotification <- chain.BlockConnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *RPCClient) onBlockDisconnected(hash *chainhash.Hash, height int32, time time.Time) {
	log.L(c.ctx).Tracef("onBlockDIsconnected [hash: %s, height: %d]", hash.String(), height)
	select {
	case c.enqueueNotification <- chain.BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRecvTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	l := log.L(c.ctx)
	l.Tracef("onRecvTx [hash: %s, block height: %d]", tx.Hash().String(), block.Height)
	blk, err := parseBlock(block)
	if err != nil {
		// Log and drop improper notification.
		l.Errorf("recvtx notification bad block: %v", err)
		return
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.MsgTx(), time.Now())
	if err != nil {
		l.Errorf("Cannot create transaction record for relevant "+
			"tx: %v", err)
		return
	}
	select {
	case c.enqueueNotification <- chain.RelevantTx{rec, blk}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRedeemingTx(tx *btcutil.Tx, block *btcjson.BlockDetails) {
	// Handled exactly like recvtx notifications.
	c.onRecvTx(tx, block)
}

func (c *RPCClient) onRescanProgress(hash *chainhash.Hash, height int32, blkTime time.Time) {
	log.L(c.ctx).Tracef("onRescanProgress [hash: %s, height: %d]", hash.String(), height)
	select {
	case c.enqueueNotification <- &chain.RescanProgress{hash, height, blkTime}:
	case <-c.quit:
	}
}

func (c *RPCClient) onRescanFinished(hash *chainhash.Hash, height int32, blkTime time.Time) {
	log.L(c.ctx).Tracef("onRescanFinished [hash: %s, height: %d]", hash.String(), height)
	select {
	case c.enqueueNotification <- &chain.RescanFinished{hash, height, blkTime}:
	case <-c.quit:
	}

}

func (c *RPCClient) addRelevantTx(dbtx walletdb.ReadWriteTx, rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {
	l := log.L(c.ctx)
	l.Infof("\tAdding relevant tx to wallet db: hash=%s, height=%d\n", rec.Hash.String(), block.Height)
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	exists, err := c.TxStore.InsertTxCheckIfExists(txmgrNs, rec, block)
	l.Infof("\tChecking if the tx already exists: %t\n", exists)
	if err != nil {
		return err
	}

	// If the transaction has already been recorded, we can return early.
	// Note: Returning here is safe as we're within the context of an atomic
	// database transaction, so we don't need to worry about the MarkUsed
	// calls below.
	if exists {
		return nil
	}

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range rec.MsgTx.TxOut {
		l.Infof("\t\tProcessing tx output %d: %+v\n", i, output)
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, c.chainParams)
		l.Infof("\t\tExtracted pub key script addresses: %+v\n", addrs)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}
		for _, addr := range addrs {
			l.Infof("\t\t\tProcessing extracted address %+v\n", addr)
			ma, err := c.Manager.Address(addrmgrNs, addr)
			l.Infof("\t\t\tAdding credit for %+v (err: %s)\n", ma, err)
			if err == nil || waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				l.Infof("\t\t\tCalling AddCredit on index %v\n", i)
				changeAddr := ma != nil && ma.Internal()
				err = c.TxStore.AddCredit(txmgrNs, rec, block, uint32(i),
					changeAddr)
				if err != nil {
					return err
				}
				// err = c.Manager.MarkUsed(addrmgrNs, addr)
				// if err != nil {
				// 	return err
				// }
				// l.Debugf("Marked address %v used", addr)
				continue
			} else {
				l.Errorf("\t\t\tSkipping adding credits due to error %s", err)
			}

			// Missing addresses are skipped.  Other errors should
			// be propagated.
			if !waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				return err
			}
		}
	}

	return nil
}

func (c *RPCClient) catchUpHashes(height int32) error {
	// TODO(aakselrod): There's a race condition here, which
	// happens when a reorg occurs between the
	// rescanProgress notification and the last GetBlockHash
	// call. The solution when using btcd is to make btcd
	// send blockconnected notifications with each block
	// the way Neutrino does, and get rid of the loop. The
	// other alternative is to check the final hash and,
	// if it doesn't match the original hash returned by
	// the notification, to roll back and restart the
	// rescan.
	l := log.L(c.ctx)
	l.Infof("Catching up block hashes to height %d, this"+
		" might take a while", height)
	err := walletdb.Update(c.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		startBlock := c.Manager.SyncedTo()

		for i := startBlock.Height + 1; i <= height; i++ {
			hash, err := c.GetBlockHash(int64(i))
			if err != nil {
				return err
			}
			header, err := c.GetBlockHeader(hash)
			if err != nil {
				return err
			}

			bs := waddrmgr.BlockStamp{
				Height:    i,
				Hash:      *hash,
				Timestamp: header.Timestamp,
			}
			err = c.Manager.SetSyncedTo(ns, &bs)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		l.Errorf("Failed to update address manager "+
			"sync state for height %d: %v", height, err)
	}

	l.Info("Done catching up block hashes")
	return err
}
