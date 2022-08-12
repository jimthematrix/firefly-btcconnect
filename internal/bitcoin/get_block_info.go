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

package bitcoin

import (
	"context"
	"encoding/json"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/hyperledger/firefly-btcconnect/internal/msgs"
	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/i18n"
)

// blockInfoJSONRPC are the fields we parse from the JSON/RPC response
type blockInfoJSONRPC struct {
	Number       int32    `json:"height"`
	Hash         string   `json:"hash"`
	ParentHash   string   `json:"previousblockhash"`
	Timestamp    int64    `json:"time"`
	Transactions []string `json:"tx"`
}

type BlockHash string

func transformBlockInfo(block *wire.MsgBlock, t *ffcapi.BlockInfo) {
	t.BlockHash = block.BlockHash().String()
	t.ParentHash = block.Header.PrevBlock.String()
	txhashes := make([]string, len(block.Transactions))
	for i, tx := range block.Transactions {
		txhashes[i] = tx.TxHash().String()
	}
	t.TransactionHashes = txhashes
}

func (c *btcConnector) getBlockInfoByNumber(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.GetBlockInfoByNumberRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	blockNumber := req.BlockNumber
	blockHash, err := c.backend.GetBlockHash(blockNumber.Int64())
	if err != nil {
		return nil, "", err
	}

	if blockHash.String() == "null" {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	block, err := c.backend.GetBlock(blockHash)
	if err != nil {
		return nil, "", err
	}

	res := &ffcapi.GetBlockInfoByNumberResponse{}
	transformBlockInfo(block, &res.BlockInfo)
	res.BlockInfo.BlockNumber = blockNumber
	return res, "", nil

}

func (c *btcConnector) getBlockInfoByHash(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.GetBlockInfoByHashRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	blkHash, err := chainhash.NewHashFromStr(req.BlockHash)
	if err != nil {
		return nil, "", err
	}
	block, err := c.backend.GetBlock(blkHash)
	if err != nil {
		return nil, "", err
	}
	if block == nil {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	res := &ffcapi.GetBlockInfoByHashResponse{}
	transformBlockInfo(block, &res.BlockInfo)
	return res, "", nil

}
