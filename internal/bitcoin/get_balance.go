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

	"github.com/hyperledger/firefly-common/pkg/ffcapi"
)

type GetBalanceRequest struct {
	ffcapi.RequestBase
	Address string `json:"address"`
}

type GetBalanceResponse struct {
	ffcapi.ResponseBase
	Amount float64 `json:"amount:`
}

func (c *btcConnector) getBalance(ctx context.Context, payload []byte) (interface{}, ffcapi.ErrorReason, error) {

	var req GetBalanceRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		return nil, ffcapi.ErrorReasonInvalidInputs, err
	}

	addr := req.Address
	amount, err := c.backend.GetBalance(addr)
	if err != nil {
		return nil, "", err
	}

	res := &GetBalanceResponse{}
	res.Amount = amount
	return res, "", nil

}
