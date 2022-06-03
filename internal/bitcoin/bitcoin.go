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
	"math/big"

	"github.com/hyperledger/firefly-btcconnect/internal/ffconnector"
	"github.com/hyperledger/firefly-btcconnect/internal/jsonrpc"
	"github.com/hyperledger/firefly-btcconnect/internal/msgs"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/i18n"
)

type btcConnector struct {
	backend             jsonrpc.Client
	gasEstimationFactor *big.Float
}

func NewBitcoinConnector(conf config.Section) ffconnector.Connector {
	return &btcConnector{}
}

func (c *btcConnector) HandlerMap() map[ffcapi.RequestType]ffconnector.FFCHandler {
	return map[ffcapi.RequestType]ffconnector.FFCHandler{
		ffcapi.RequestTypeCreateBlockListener: c.createBlockListener,
		// ffcapi.RequestTypeExecQuery:            c.execQuery,
		ffcapi.RequestTypeGetBlockInfoByHash:   c.getBlockInfoByHash,
		ffcapi.RequestTypeGetBlockInfoByNumber: c.getBlockInfoByNumber,
		// ffcapi.RequestTypeGetGasPrice:          c.getGasPrice,
		ffcapi.RequestTypeGetNewBlockHashes: c.getNewBlockHashes,
		// ffcapi.RequestTypeGetNextNonce:         c.getNextNonce,
		// ffcapi.RequestTypeGetReceipt:           c.getReceipt,
		// ffcapi.RequestTypePrepareTransaction:   c.prepareTransaction,
		// ffcapi.RequestTypeSendTransaction:      c.sendTransaction,
	}
}

func (c *btcConnector) Init(ctx context.Context, conf config.Section) error {
	if conf.GetString(ffresty.HTTPConfigURL) == "" {
		return i18n.NewError(ctx, msgs.MsgMissingBackendURL)
	}
	c.gasEstimationFactor = big.NewFloat(conf.GetFloat64(ConfigGasEstimationFactor))
	c.backend = jsonrpc.NewRPCClient(ffresty.New(ctx, conf))
	return nil
}
