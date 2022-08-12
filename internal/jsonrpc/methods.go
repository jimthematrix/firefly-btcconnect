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
	"errors"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/hyperledger/firefly-common/pkg/log"
)

// GetCurrentNet returns the network the server is running on.
func (c *RPCClient) GetCurrentNet() (wire.BitcoinNet, error) {
	cmd := btcjson.NewGetCurrentNetCmd()
	var result FutureGetCurrentNetResult
	result = c.SendCmd(cmd)
	return result.Receive()
}

// GetBlockChainInfo returns information related to the processing state of
// various chain-specific details such as the current difficulty from the tip
// of the main chain.
func (c *RPCClient) GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error) {
	cmd := btcjson.NewGetBlockChainInfoCmd()
	return FutureGetBlockChainInfoResult{
		client:   c,
		Response: c.SendCmd(cmd),
	}.Receive()
}

// GetInfo returns miscellaneous info regarding the RPC server.  The returned
// info object may be void of wallet information if the remote server does
// not include wallet functionality.
func (c *RPCClient) GetInfo() (*btcjson.InfoWalletResult, error) {
	cmd := btcjson.NewGetInfoCmd()
	var result FutureGetInfoResult
	result = c.SendCmd(cmd)
	return result.Receive()
}

// GetNetworkInfo returns data about the current network.
func (c *RPCClient) GetNetworkInfo() (*btcjson.GetNetworkInfoResult, error) {
	cmd := btcjson.NewGetNetworkInfoCmd()
	var result FutureGetNetworkInfoResult
	result = c.SendCmd(cmd)
	return result.Receive()
}

// GetCFilterAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *RPCClient) GetCFilter(blockHash *chainhash.Hash,
	filterType wire.FilterType) (*wire.MsgCFilter, error) {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetCFilterCmd(hash, filterType)
	var result FutureGetCFilterResult
	result = c.SendCmd(cmd)
	ret, err := result.Receive()
	if err != nil {
		log.L(c.ctx).Errorf("Failed to receive promised value. %s", err)
		return nil, err
	}
	return ret, nil
}

// GetBlockHeaderVerbose returns a data structure with information about the
// blockheader from the server given its hash.
func (c *RPCClient) GetBlockHeaderVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error) {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetBlockHeaderCmd(hash, btcjson.Bool(true))
	var result FutureGetBlockHeaderVerboseResult
	result = c.SendCmd(cmd)
	return result.Receive()
}

// GetBlock returns a raw block from the server given its hash.
func (c *RPCClient) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetBlockCmd(hash, btcjson.Int(0))
	result := FutureGetBlockResult{
		client:   c,
		hash:     hash,
		Response: c.SendCmd(cmd),
	}
	return result.Receive()
}

// GetBlockHeader returns the blockheader from the server given its hash.
//
// See GetBlockHeaderVerbose to retrieve a data structure with information about the
// block instead.
func (c *RPCClient) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}

	cmd := btcjson.NewGetBlockHeaderCmd(hash, btcjson.Bool(false))
	var result FutureGetBlockHeaderResult
	result = c.SendCmd(cmd)
	return result.Receive()
}

// GetBlockHash returns the hash of the block in the best block chain at the
// given height.
func (c *RPCClient) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	cmd := btcjson.NewGetBlockHashCmd(blockHeight)
	var result FutureGetBlockHashResult
	result = c.SendCmd(cmd)
	return result.Receive()
}

// GetBlockVerbose returns a data structure from the server with information
// about a block given its hash.
//
// See GetBlockVerboseTx to retrieve transaction data structures as well.
// See GetBlock to retrieve a raw block instead.
func (c *RPCClient) GetBlockVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseResult, error) {
	hash := ""
	if blockHash != nil {
		hash = blockHash.String()
	}
	// From the bitcoin-cli getblock documentation:
	// "If verbosity is 1, returns an Object with information about block ."
	cmd := btcjson.NewGetBlockCmd(hash, btcjson.Int(1))
	result := FutureGetBlockVerboseResult{
		client:   c,
		hash:     hash,
		Response: c.SendCmd(cmd),
	}
	return result.Receive()
}

// getBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func (c *RPCClient) GetBalance(account string) (float64, error) {
	var balance btcutil.Amount
	var err error
	accountName := "*"
	if account != "" {
		accountName = account
	}
	if accountName == "*" {
		balance, err = c.calculateBalance(int32(1))
		if err != nil {
			return 0, err
		}
	} else {
		var account uint32
		account, err = c.accountNumber(waddrmgr.KeyScopeBIP0044, accountName)
		if err != nil {
			return 0, err
		}
		bals, err := c.calculateAccountBalances(account, int32(1))
		if err != nil {
			return 0, err
		}
		balance = bals.Spendable
	}
	return balance.ToBTC(), nil
}

////////////////////////////
// Supporting Definitions
////////////////////////////

// FutureGetCurrentNetResult is a future promise to deliver the result of a
// GetCurrentNetAsync RPC invocation (or an applicable error).
type FutureGetCurrentNetResult chan *Response

// Receive waits for the Response promised by the future and returns the network
// the server is running on.
func (r FutureGetCurrentNetResult) Receive() (wire.BitcoinNet, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return 0, err
	}

	// Unmarshal result as an int64.
	var net int64
	err = json.Unmarshal(res, &net)
	if err != nil {
		return 0, err
	}

	return wire.BitcoinNet(net), nil
}

// ReceiveFuture receives from the passed futureResult channel to extract a
// reply or any errors.  The examined errors include an error in the
// futureResult and the error in the reply from the server.  This will block
// until the result is available on the passed channel.
func ReceiveFuture(f chan *Response) ([]byte, error) {
	// Wait for a response on the returned channel.
	r := <-f
	return r.result, r.err
}

// FutureGetBlockChainInfoResult is a promise to deliver the result of a
// GetBlockChainInfoAsync RPC invocation (or an applicable error).
type FutureGetBlockChainInfoResult struct {
	client   *RPCClient
	Response chan *Response
}

// unmarshalPartialGetBlockChainInfoResult unmarshals the response into an
// instance of GetBlockChainInfoResult without populating the SoftForks and
// UnifiedSoftForks fields.
func unmarshalPartialGetBlockChainInfoResult(res []byte) (*btcjson.GetBlockChainInfoResult, error) {
	var chainInfo btcjson.GetBlockChainInfoResult
	if err := json.Unmarshal(res, &chainInfo); err != nil {
		return nil, err
	}
	return &chainInfo, nil
}

// unmarshalGetBlockChainInfoResultSoftForks properly unmarshals the softforks
// related fields into the GetBlockChainInfoResult instance.
func unmarshalGetBlockChainInfoResultSoftForks(chainInfo *btcjson.GetBlockChainInfoResult,
	version rpcclient.BackendVersion, res []byte) error {

	switch version {
	// Versions of bitcoind on or after v0.19.0 use the unified format.
	case rpcclient.BitcoindPost19:
		var softForks btcjson.UnifiedSoftForks
		if err := json.Unmarshal(res, &softForks); err != nil {
			return err
		}
		chainInfo.UnifiedSoftForks = &softForks

	// All other versions use the original format.
	default:
		var softForks btcjson.SoftForks
		if err := json.Unmarshal(res, &softForks); err != nil {
			return err
		}
		chainInfo.SoftForks = &softForks
	}

	return nil
}

// Receive waits for the Response promised by the future and returns chain info
// result provided by the server.
func (r FutureGetBlockChainInfoResult) Receive() (*btcjson.GetBlockChainInfoResult, error) {
	res, err := ReceiveFuture(r.Response)
	if err != nil {
		return nil, err
	}
	chainInfo, err := unmarshalPartialGetBlockChainInfoResult(res)
	if err != nil {
		return nil, err
	}

	// Inspect the version to determine how we'll need to parse the
	// softforks from the response.
	version, err := r.client.BackendVersion()
	if err != nil {
		return nil, err
	}

	err = unmarshalGetBlockChainInfoResultSoftForks(chainInfo, version, res)
	if err != nil {
		return nil, err
	}

	return chainInfo, nil
}

type FutureGetInfoResult chan *Response

// Receive waits for the Response promised by the future and returns the info
// provided by the server.
func (r FutureGetInfoResult) Receive() (*btcjson.InfoWalletResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a getinfo result object.
	var infoRes btcjson.InfoWalletResult
	err = json.Unmarshal(res, &infoRes)
	if err != nil {
		return nil, err
	}

	return &infoRes, nil
}

// FutureGetNetworkInfoResult is a future promise to deliver the result of a
// GetNetworkInfoAsync RPC invocation (or an applicable error).
type FutureGetNetworkInfoResult chan *Response

// Receive waits for the Response promised by the future and returns data about
// the current network.
func (r FutureGetNetworkInfoResult) Receive() (*btcjson.GetNetworkInfoResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as an array of getpeerinfo result objects.
	var networkInfo btcjson.GetNetworkInfoResult
	err = json.Unmarshal(res, &networkInfo)
	if err != nil {
		return nil, err
	}

	return &networkInfo, nil
}

// FutureGetCFilterResult is a future promise to deliver the result of a
// GetCFilterAsync RPC invocation (or an applicable error).
type FutureGetCFilterResult chan *Response

// Receive waits for the Response promised by the future and returns the raw
// filter requested from the server given its block hash.
func (r FutureGetCFilterResult) Receive() (*wire.MsgCFilter, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var filterHex string
	err = json.Unmarshal(res, &filterHex)
	if err != nil {
		return nil, err
	}

	// Decode the serialized cf hex to raw bytes.
	serializedFilter, err := hex.DecodeString(filterHex)
	if err != nil {
		return nil, err
	}

	// Assign the filter bytes to the correct field of the wire message.
	// We aren't going to set the block hash or extended flag, since we
	// don't actually get that back in the RPC response.
	var msgCFilter wire.MsgCFilter
	msgCFilter.Data = serializedFilter
	return &msgCFilter, nil
}

// FutureGetBlockHeaderVerboseResult is a future promise to deliver the result of a
// GetBlockAsync RPC invocation (or an applicable error).
type FutureGetBlockHeaderVerboseResult chan *Response

// Receive waits for the Response promised by the future and returns the
// data structure of the blockheader requested from the server given its hash.
func (r FutureGetBlockHeaderVerboseResult) Receive() (*btcjson.GetBlockHeaderVerboseResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var bh btcjson.GetBlockHeaderVerboseResult
	err = json.Unmarshal(res, &bh)
	if err != nil {
		return nil, err
	}

	return &bh, nil
}

// FutureGetBlockResult is a future promise to deliver the result of a
// GetBlockAsync RPC invocation (or an applicable error).
type FutureGetBlockResult struct {
	client   *RPCClient
	hash     string
	Response chan *Response
}

// Receive waits for the Response promised by the future and returns the raw
// block requested from the server given its hash.
func (r FutureGetBlockResult) Receive() (*wire.MsgBlock, error) {
	res, err := r.client.waitForGetBlockRes(r.Response, r.hash, false, false)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var blockHex string
	err = json.Unmarshal(res, &blockHex)
	if err != nil {
		return nil, err
	}

	// Decode the serialized block hex to raw bytes.
	serializedBlock, err := hex.DecodeString(blockHex)
	if err != nil {
		return nil, err
	}

	// Deserialize the block and return it.
	var msgBlock wire.MsgBlock
	err = msgBlock.Deserialize(bytes.NewReader(serializedBlock))
	if err != nil {
		return nil, err
	}
	return &msgBlock, nil
}

// waitForGetBlockRes waits for the Response of a getblock request. If the
// Response indicates an invalid parameter was provided, a legacy style of the
// request is resent and its Response is returned instead.
func (c *RPCClient) waitForGetBlockRes(respChan chan *Response, hash string,
	verbose, verboseTx bool) ([]byte, error) {

	res, err := ReceiveFuture(respChan)

	// If we receive an invalid parameter error, then we may be
	// communicating with a btcd node which only understands the legacy
	// request, so we'll try that.
	if err, ok := err.(*btcjson.RPCError); ok &&
		err.Code == btcjson.ErrRPCInvalidParams.Code {
		return c.legacyGetBlockRequest(hash, verbose, verboseTx)
	}

	// Otherwise, we can return the Response as is.
	return res, err
}

// legacyGetBlockRequest constructs and sends a legacy getblock request which
// contains two separate bools to denote verbosity, in contract to a single int
// parameter.
func (c *RPCClient) legacyGetBlockRequest(hash string, verbose,
	verboseTx bool) ([]byte, error) {

	hashJSON, err := json.Marshal(hash)
	if err != nil {
		return nil, err
	}
	verboseJSON, err := json.Marshal(btcjson.Bool(verbose))
	if err != nil {
		return nil, err
	}
	verboseTxJSON, err := json.Marshal(btcjson.Bool(verboseTx))
	if err != nil {
		return nil, err
	}
	return c.RawRequest("getblock", []json.RawMessage{
		hashJSON, verboseJSON, verboseTxJSON,
	})
}

// FutureRawResult is a future promise to deliver the result of a RawRequest RPC
// invocation (or an applicable error).
type FutureRawResult chan *Response

// Receive waits for the Response promised by the future and returns the raw
// response, or an error if the request was unsuccessful.
func (r FutureRawResult) Receive() (json.RawMessage, error) {
	return ReceiveFuture(r)
}

// RawRequest allows the caller to send a raw or custom request to the server.
// This method may be used to send and receive requests and responses for
// requests that are not handled by this client package, or to proxy partially
// unmarshaled requests to another JSON-RPC server if a request cannot be
// handled directly.
func (c *RPCClient) RawRequest(method string, params []json.RawMessage) (json.RawMessage, error) {
	// Method may not be empty.
	if method == "" {
		return nil, errors.New("no method")
	}

	// Marshal parameters as "[]" instead of "null" when no parameters
	// are passed.
	if params == nil {
		params = []json.RawMessage{}
	}

	// Create a raw JSON-RPC request using the provided method and params
	// and marshal it.  This is done rather than using the SendCmd function
	// since that relies on marshalling registered btcjson commands rather
	// than custom commands.
	id := c.NextID()
	rawRequest := &btcjson.Request{
		Jsonrpc: btcjson.RpcVersion1,
		ID:      id,
		Method:  method,
		Params:  params,
	}
	marshalledJSON, err := json.Marshal(rawRequest)
	if err != nil {
		return nil, err
	}

	// Generate the request and send it along with a channel to respond on.
	responseChan := make(chan *Response, 1)
	jReq := &jsonRequest{
		id:             id,
		method:         method,
		cmd:            nil,
		marshalledJSON: marshalledJSON,
		responseChan:   responseChan,
	}
	c.sendRequest(jReq)

	var result FutureRawResult
	result = responseChan
	return result.Receive()
}

// FutureGetBlockHashResult is a future promise to deliver the result of a
// GetBlockHashAsync RPC invocation (or an applicable error).
type FutureGetBlockHashResult chan *Response

// Receive waits for the Response promised by the future and returns the hash of
// the block in the best block chain at the given height.
func (r FutureGetBlockHashResult) Receive() (*chainhash.Hash, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal the result as a string-encoded sha.
	var txHashStr string
	err = json.Unmarshal(res, &txHashStr)
	if err != nil {
		return nil, err
	}
	return chainhash.NewHashFromStr(txHashStr)
}

// FutureGetBlockHeaderResult is a future promise to deliver the result of a
// GetBlockHeaderAsync RPC invocation (or an applicable error).
type FutureGetBlockHeaderResult chan *Response

// Receive waits for the Response promised by the future and returns the
// blockheader requested from the server given its hash.
func (r FutureGetBlockHeaderResult) Receive() (*wire.BlockHeader, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a string.
	var bhHex string
	err = json.Unmarshal(res, &bhHex)
	if err != nil {
		return nil, err
	}

	serializedBH, err := hex.DecodeString(bhHex)
	if err != nil {
		return nil, err
	}

	// Deserialize the blockheader and return it.
	var bh wire.BlockHeader
	err = bh.Deserialize(bytes.NewReader(serializedBH))
	if err != nil {
		return nil, err
	}

	return &bh, err
}

// FutureGetBlockVerboseResult is a future promise to deliver the result of a
// GetBlockVerboseAsync RPC invocation (or an applicable error).
type FutureGetBlockVerboseResult struct {
	client   *RPCClient
	hash     string
	Response chan *Response
}

// Receive waits for the Response promised by the future and returns the data
// structure from the server with information about the requested block.
func (r FutureGetBlockVerboseResult) Receive() (*btcjson.GetBlockVerboseResult, error) {
	res, err := r.client.waitForGetBlockRes(r.Response, r.hash, true, false)
	if err != nil {
		return nil, err
	}

	// Unmarshal the raw result into a BlockResult.
	var blockResult btcjson.GetBlockVerboseResult
	err = json.Unmarshal(res, &blockResult)
	if err != nil {
		return nil, err
	}
	return &blockResult, nil
}
