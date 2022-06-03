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
	"math/big"

	"github.com/hyperledger/firefly-btcconnect/internal/msgs"
	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/fftypes"
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

func transformBlockInfo(bi *blockInfoJSONRPC, t *ffcapi.BlockInfo) {
	t.BlockNumber = (*fftypes.FFBigInt)(big.NewInt(int64(bi.Number)))
	t.BlockHash = bi.Hash
	t.ParentHash = bi.ParentHash
	stringHashes := make([]string, len(bi.Transactions))
	copy(stringHashes, bi.Transactions)
	t.TransactionHashes = stringHashes
}

func (c *btcConnector) getBlockInfoByNumber(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.GetBlockInfoByNumberRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	blockNumber := req.BlockNumber
	var blockHash string
	err = c.backend.Invoke(ctx, &blockHash, "getblockhash", blockNumber)
	if err != nil {
		return nil, "", err
	}
	if blockHash == "null" {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	var blockInfo *blockInfoJSONRPC
	err = c.backend.Invoke(ctx, &blockInfo, "getblock", blockHash)
	if err != nil {
		return nil, "", err
	}
	if blockInfo == nil {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	res := &ffcapi.GetBlockInfoByNumberResponse{}
	transformBlockInfo(blockInfo, &res.BlockInfo)
	return res, "", nil

}

func (c *btcConnector) getBlockInfoByHash(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req ffcapi.GetBlockInfoByHashRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	var blockInfo *blockInfoJSONRPC
	err = c.backend.Invoke(ctx, &blockInfo, "getblock", req.BlockHash)
	if err != nil {
		return nil, "", err
	}
	if blockInfo == nil {
		return nil, ffcapi.ErrorReasonNotFound, i18n.NewError(ctx, msgs.MsgBlockNotAvailable)
	}

	res := &ffcapi.GetBlockInfoByHashResponse{}
	transformBlockInfo(blockInfo, &res.BlockInfo)
	return res, "", nil

}
