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
	"errors"
	"sync/atomic"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/hyperledger/firefly-common/pkg/log"
)

// jsonRequest holds information about a json request that is used to properly
// detect, interpret, and deliver a reply to it.
type jsonRequest struct {
	id             uint64
	method         string
	cmd            interface{}
	marshalledJSON []byte
	responseChan   chan *Response
}

// SendCmd sends the passed command to the associated server and returns a
// response channel on which the reply will be delivered at some point in the
// future.  It handles both websocket and HTTP POST mode depending on the
// configuration of the client.
func (c *RPCClient) SendCmd(cmd interface{}) chan *Response {
	rpcVersion := btcjson.RpcVersion1
	// Get the method associated with the command.
	method, err := btcjson.CmdMethod(cmd)
	if err != nil {
		return newFutureError(err)
	}

	// Marshal the command.
	id := c.NextID()
	marshalledJSON, err := btcjson.MarshalCmd(rpcVersion, id, cmd)
	if err != nil {
		return newFutureError(err)
	}

	// Generate the request and send it along with a channel to respond on.
	responseChan := make(chan *Response, 1)
	jReq := &jsonRequest{
		id:             id,
		method:         method,
		cmd:            cmd,
		marshalledJSON: marshalledJSON,
		responseChan:   responseChan,
	}

	c.sendRequest(jReq)

	return responseChan
}

// NextID returns the next id to be used when sending a JSON-RPC message.  This
// ID allows responses to be associated with particular requests per the
// JSON-RPC specification.  Typically the consumer of the client does not need
// to call this function, however, if a custom request is being created and used
// this function should be used to ensure the ID is unique amongst all requests
// being made.
func (c *RPCClient) NextID() uint64 {
	return atomic.AddUint64(&c.nextRPCRequestID, 1)
}

// sendRequest sends the passed json request to the associated server using the
// provided response channel for the reply.  It handles both websocket and HTTP
// POST mode depending on the configuration of the client.
func (c *RPCClient) sendRequest(jReq *jsonRequest) {
	// Choose which marshal and send function to use depending on whether
	// the client running in HTTP POST mode or not.  When running in HTTP
	// POST mode, the command is issued via an HTTP client.  Otherwise,
	// the command is issued via the asynchronous websocket channels.
	if c.httpClient != nil {
		c.sendPostRequest(jReq)
		return
	}

	// Add the request to the internal tracking map so the response from the
	// remote server can be properly detected and routed to the response
	// channel.  Then send the marshalled request via the websocket
	// connection.
	if err := c.addRequest(jReq); err != nil {
		jReq.responseChan <- &Response{err: err}
		return
	}
	log.L(c.ctx).Tracef("Sending command [%s] with id %d", jReq.method, jReq.id)
	c.sendMessage(jReq.marshalledJSON)
}

// sendMessage sends the passed JSON to the connected server using the
// websocket connection.  It is backed by a buffered channel, so it will not
// block until the send channel is full.
func (c *RPCClient) sendMessage(marshalledJSON []byte) {
	// Don't send the message if disconnected.
	select {
	case c.sendChan <- marshalledJSON:
	case <-c.disconnectChan():
		return
	}
}

// disconnectChan returns a copy of the current disconnect channel.  The channel
// is read protected by the client mutex, and is safe to call while the channel
// is being reassigned during a reconnect.
func (c *RPCClient) disconnectChan() <-chan struct{} {
	c.mtx.Lock()
	ch := c.disconnect
	c.mtx.Unlock()
	return ch
}

// sendPostRequest sends the passed HTTP request to the RPC server using the
// HTTP client associated with the client.  It is backed by a buffered channel,
// so it will not block until the send channel is full.
func (c *RPCClient) sendPostRequest(jReq *jsonRequest) {
	// Don't send the message if shutting down.
	select {
	case <-c.shutdown:
		jReq.responseChan <- &Response{result: nil, err: ErrClientShutdown}
	default:
	}

	log.L(c.ctx).Tracef("Sending command [%s] with id %d", jReq.method, jReq.id)

	c.sendPostChan <- jReq
}

// addRequest associates the passed jsonRequest with its id.  This allows the
// response from the remote server to be unmarshalled to the appropriate type
// and sent to the specified channel when it is received.
//
// If the client has already begun shutting down, ErrClientShutdown is returned
// and the request is not added.
//
// This function is safe for concurrent access.
func (c *RPCClient) addRequest(jReq *jsonRequest) error {
	c.requestLock.Lock()
	defer c.requestLock.Unlock()

	// A non-blocking read of the shutdown channel with the request lock
	// held avoids adding the request to the client's internal data
	// structures if the client is in the process of shutting down (and
	// has not yet grabbed the request lock), or has finished shutdown
	// already (responding to each outstanding request with
	// ErrClientShutdown).
	select {
	case <-c.shutdown:
		return ErrClientShutdown
	default:
	}

	element := c.requestList.PushBack(jReq)
	c.requestMap[jReq.id] = element
	return nil
}

// ErrClientShutdown is an error to describe the condition where the
// client is either already shutdown, or in the process of shutting
// down.  Any outstanding futures when a client shutdown occurs will
// return this error as will any new requests.
var ErrClientShutdown = errors.New("the client has been shutdown")

// Response is the raw bytes of a JSON-RPC result, or the error if the response
// error object was non-null.
type Response struct {
	result []byte
	err    error
}

// newFutureError returns a new future result channel that already has the
// passed error waitin on the channel with the reply set to nil.  This is useful
// to easily return errors from the various Async functions.
func newFutureError(err error) chan *Response {
	responseChan := make(chan *Response, 1)
	responseChan <- &Response{err: err}
	return responseChan
}
