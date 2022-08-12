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
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// GetBestBlock returns the highest block known to bitcoind.
func (c *RPCClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	bcinfo, err := c.GetBlockChainInfo()
	if err != nil {
		return nil, 0, err
	}

	hash, err := chainhash.NewHashFromStr(bcinfo.BestBlockHash)
	if err != nil {
		return nil, 0, err
	}

	return hash, bcinfo.Blocks, nil
}

// GetBlockHeight returns the height for the hash, if known, or returns an
// error.
func (c *RPCClient) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	header, err := c.GetBlockHeaderVerbose(hash)
	if err != nil {
		return 0, err
	}

	return header.Height, nil
}
