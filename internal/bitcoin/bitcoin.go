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
	"fmt"
	"strings"

	"github.com/btcsuite/btcwallet/netparams"
	"github.com/go-resty/resty/v2"
	"github.com/hyperledger/firefly-btcconnect/internal/ffconnector"
	"github.com/hyperledger/firefly-btcconnect/internal/jsonrpc"
	"github.com/hyperledger/firefly-btcconnect/internal/msgs"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffcapi"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
)

type btcConnector struct {
	backend *jsonrpc.RPCClient
	ctx     context.Context
}

const (
	RequestTypeImportAddress ffcapi.RequestType = "import_address"
	RequestTypeGetBalance    ffcapi.RequestType = "get_balance"
)

func NewBitcoinConnector(conf config.Section) ffconnector.Connector {
	return &btcConnector{}
}

func (c *btcConnector) HandlerMap() map[ffcapi.RequestType]ffconnector.FFCHandler {
	return map[ffcapi.RequestType]ffconnector.FFCHandler{
		// ffcapi.RequestTypeCreateBlockListener: c.createBlockListener,
		// ffcapi.RequestTypeExecQuery:            c.execQuery,
		ffcapi.RequestTypeGetBlockInfoByHash:   c.getBlockInfoByHash,
		ffcapi.RequestTypeGetBlockInfoByNumber: c.getBlockInfoByNumber,
		RequestTypeImportAddress:               c.importAddress,
		RequestTypeGetBalance:                  c.getBalance,
		// ffcapi.RequestTypeGetGasPrice:          c.getGasPrice,
		// ffcapi.RequestTypeGetNewBlockHashes: c.getNewBlockHashes,
		// ffcapi.RequestTypeGetNextNonce:         c.getNextNonce,
		// ffcapi.RequestTypeGetReceipt:           c.getReceipt,
		// ffcapi.RequestTypePrepareTransaction:   c.prepareTransaction,
		// ffcapi.RequestTypeSendTransaction:      c.sendTransaction,
	}
}

func (c *btcConnector) Init(ctx context.Context, conf config.Section) error {
	c.ctx = log.WithLogField(ctx, "proto", "bitcoin")

	url := conf.GetString(ffresty.HTTPConfigURL)
	if url == "" {
		return i18n.NewError(ctx, msgs.MsgMissingBackendURL)
	}

	useWebsocket := false
	if strings.HasPrefix(url, "ws") || conf.GetString(wsclient.WSConfigKeyPath) != "" {
		useWebsocket = true
	}
	username := conf.GetString(ffresty.HTTPConfigAuthUsername)
	password := conf.GetString(ffresty.HTTPConfigAuthPassword)
	basicToken := conf.GetString("auth.basicToken")
	bearerToken := conf.GetString("auth.bearerToken")
	fmt.Printf("bearer: %s, basic: %s, username: %s, password: %s\n", bearerToken, basicToken, username, password)
	if bearerToken == "" && basicToken == "" && (username == "" || password == "") {
		return i18n.NewError(ctx, "Must specify one of auth.basicToken, auth.bearerToken, or auth.username + auth.password")
	}

	activeNet := &netparams.MainNetParams
	if conf.GetString("network") == "testnet" {
		activeNet = &netparams.TestNet3Params
	}

	var client interface{}
	if useWebsocket {
		wsclient, err := newWSClient(ctx, conf, basicToken, username, password)
		if err != nil {
			return err
		}
		client = wsclient
	} else {
		client = newHttpClient(ctx, conf, bearerToken, basicToken, username, password)
	}

	rpcclient := jsonrpc.NewRPCClient(ctx, client, activeNet.Params)
	err := rpcclient.Start()
	if err != nil {
		return err
	}
	c.backend = rpcclient

	return nil
}

func newHttpClient(ctx context.Context, conf config.Section, bearerToken, basicToken, username, password string) *resty.Client {
	client := ffresty.New(ctx, conf)
	switch {
	case bearerToken != "":
		client.SetAuthToken(bearerToken)
	case basicToken != "":
		client.SetAuthScheme("Basic")
		client.SetAuthToken(basicToken)
	default:
		client.SetBasicAuth(username, password)
	}

	return client
}
