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
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/go-resty/resty/v2"
	"github.com/hyperledger/firefly-btcconnect/internal/msgs"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
)

type Client interface {
	Invoke(ctx context.Context, result interface{}, method string, params ...interface{}) error
}

func NewRPCClient(httpClient *resty.Client) Client {
	return &jsonRPC{
		httpClient: httpClient,
	}
}

type jsonRPC struct {
	httpClient       *resty.Client
	nextRPCRequestID int64
}

type RPCRequest struct {
	JSONRpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  []interface{}   `json:"params,omitempty"`
}

type RPCError struct {
	Code    int64         `json:"code"`
	Message string        `json:"message"`
	Data    []interface{} `json:"data,omitempty"`
}

type RPCResponse struct {
	JSONRpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

func (r *RPCResponse) Message() string {
	if r.Error != nil {
		return r.Error.Message
	}
	return ""
}

func (r *jsonRPC) Invoke(ctx context.Context, result interface{}, method string, params ...interface{}) error {
	id := atomic.AddInt64(&r.nextRPCRequestID, 1)
	rpcReq := &RPCRequest{
		JSONRpc: "2.0",
		ID:      json.RawMessage(fmt.Sprintf(`"%d"`, id)),
		Method:  method,
		Params:  params,
	}
	var rpcRes RPCResponse

	log.L(ctx).Infof("RPC:%s:%s --> %s", rpcReq.ID, rpcReq.ID, rpcReq.Method)
	res, err := r.httpClient.R().
		SetContext(ctx).
		SetBody(&rpcReq).
		SetResult(rpcRes).
		SetError(rpcRes).
		Post("")
	// Restore the original ID
	rpcRes.ID = rpcReq.ID
	if err != nil {
		err := i18n.NewError(ctx, msgs.MsgRPCRequestFailed, err)
		log.L(ctx).Errorf("RPC[%d] <-- ERROR: %s", id, err)
		return err
	}
	if res.IsError() {
		log.L(ctx).Errorf("RPC[%d] <-- [%d]: %s", id, res.StatusCode(), rpcRes.Message())
		err := fmt.Errorf(rpcRes.Message())
		return err
	}
	log.L(ctx).Infof("RPC[%d] <-- [%d] OK", id, res.StatusCode())
	if rpcRes.Result == nil {
		return nil
	}
	return json.Unmarshal(rpcRes.Result, &result)
}
