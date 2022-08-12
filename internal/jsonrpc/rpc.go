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
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync/atomic"

	"errors"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"github.com/hyperledger/firefly-btcconnect/internal/msgs"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type RPCRequest struct {
	JSONRpc string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type RPCError struct {
	Code    int64         `json:"code"`
	Message string        `json:"message"`
	Data    []interface{} `json:"data,omitempty"`
}

type RPCResponse struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

func (r *RPCResponse) Message() string {
	if r.Error != nil {
		return r.Error.Message
	}
	return ""
}

var (
	// ErrClientDisconnect is an error to describe the condition where the
	// client has been disconnected from the RPC server.  When the
	// DisableAutoReconnect option is not set, any outstanding futures
	// when a client disconnect occurs will return this error as will
	// any new requests.
	ErrClientDisconnect = errors.New("the client has been disconnected")
)

const (
	// sendBufferSize is the number of elements the websocket send channel
	// can queue before blocking.
	sendBufferSize = 50

	// sendPostBufferSize is the number of elements the HTTP POST send
	// channel can queue before blocking.
	sendPostBufferSize = 100

	dbType_Berkeley  = "bdb"
	defaultDBTimeout = 10 * time.Second
)

// RPCClient represents a persistent client connection to a bitcoin RPC server
// for information regarding the current best block chain.
type RPCClient struct {
	httpClient       *resty.Client // some bitcoin backends only supports HTTP, no websocket
	wsClient         WsClient      // for bitcoin backends that supports websocket
	nextRPCRequestID uint64
	ctx              context.Context
	chainParams      *chaincfg.Params
	backendVersionMu sync.Mutex
	backendVersion   *rpcclient.BackendVersion

	db      walletdb.DB
	Manager *waddrmgr.Manager
	TxStore *wtxmgr.Store

	enqueueNotification chan interface{}
	dequeueNotification chan interface{}
	currentBlock        chan *waddrmgr.BlockStamp

	chainClientSynced  bool
	chainClientSyncMtx sync.Mutex

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.
	rescanNotifications chan interface{} // From chain server

	// Track command and their response channels by ID.
	requestLock sync.Mutex
	requestMap  map[uint64]*list.Element
	requestList *list.List

	// mtx is a mutex to protect access to connection related fields.
	mtx sync.Mutex

	// disconnected indicated whether or not the server is disconnected.
	disconnected bool

	// Networking infrastructure.
	sendChan     chan []byte
	sendPostChan chan *jsonRequest
	disconnect   chan struct{}
	shutdown     chan struct{}

	quit    chan struct{}
	wg      sync.WaitGroup
	started bool
	quitMtx sync.Mutex
}

// NewRPCClient creates a client connection to the server described by the
// connect string.  If disableTLS is false, the remote RPC certificate must be
// provided in the certs slice.  The connection is not established immediately,
// but must be done using the Start method.  If the remote server does not
// operate on the same bitcoin network as described by the passed chain
// parameters, the connection will be disconnected.
func NewRPCClient(ctx context.Context, client interface{}, chainParams *chaincfg.Params) *RPCClient {
	var httpClient *resty.Client
	var wsClient WsClient
	switch client.(type) {
	case *resty.Client:
		httpClient = client.(*resty.Client)
	case WsClient:
		wsClient = client.(WsClient)
	}

	rpcclient := &RPCClient{
		ctx:         ctx,
		httpClient:  httpClient,
		wsClient:    wsClient,
		chainParams: chainParams,

		sendChan:     make(chan []byte, sendBufferSize),
		sendPostChan: make(chan *jsonRequest, sendPostBufferSize),
		disconnect:   make(chan struct{}),
		shutdown:     make(chan struct{}),

		rescanNotifications: make(chan interface{}),

		requestList:         list.New(),
		requestMap:          make(map[uint64]*list.Element),
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		currentBlock:        make(chan *waddrmgr.BlockStamp),
		quit:                make(chan struct{}),
	}
	return rpcclient
}

// BackEnd returns the name of the driver.
func (c *RPCClient) BackEnd() string {
	return "btcd"
}

func (c *RPCClient) GetWsClient() WsClient {
	return c.wsClient
}

// Start attempts to establish a client connection with the remote server.
// If successful, handler goroutines are started to process notifications
// sent by the server.  After a limited number of connection attempts, this
// function gives up, and therefore will not block forever waiting for the
// connection to be established to a server that may not exist.
func (c *RPCClient) Start() error {
	err := c.initDB()
	if err != nil {
		return err
	}

	c.quitMtx.Lock()
	c.started = true
	c.quitMtx.Unlock()

	c.wg.Add(1)
	go c.handleChainNotifications()
	go c.handler()
	go c.wsInHandler()
	go c.wsOutHandler()

	// Verify that the server is running on the expected network.
	net, err := c.GetCurrentNet()
	if err != nil {
		return err
	}
	if net != c.chainParams.Net {
		return errors.New("mismatched networks")
	}
	return nil
}

// Stop disconnects the client and signals the shutdown of all goroutines
// started by Start.
func (c *RPCClient) Stop() {
	c.quitMtx.Lock()
	select {
	case <-c.quit:
	default:
		close(c.quit)
		if c.wsClient != nil {
			c.wsClient.Close()
		}

		if !c.started {
			close(c.dequeueNotification)
		}
	}
	c.quitMtx.Unlock()
}

func (c *RPCClient) initDB() error {
	l := log.L(c.ctx)
	db, err := walletdb.Create(dbType_Berkeley, "/tmp/bdb", true, defaultDBTimeout)
	if err != nil {
		l.Errorf("Failed to create the database: %s\n", err)
		return err
	}
	hdSeed, err := hdkeychain.GenerateSeed(
		hdkeychain.RecommendedSeedLen,
	)
	if err != nil {
		l.Errorf("Failed to generate seed for the key: %s\n", err)
		return err
	}

	// Derive the master extended key from the seed.
	rootKey, err := hdkeychain.NewMaster(hdSeed, c.chainParams)
	if err != nil {
		l.Errorf("Failed to derive master extended key: %s\n", err)
		return fmt.Errorf("failed to derive master extended key")
	}
	walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			l.Errorf("Failed to create top level bucket for the waddrmgr: %s\n", err)
			return err
		}
		txmgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			l.Errorf("Failed to create top level bucket for the wtxmgr: %s\n", err)
			return err
		}

		err = waddrmgr.Create(addrmgrNs, rootKey, []byte(""), []byte("secret"), c.chainParams, nil, time.Now())
		if err != nil {
			l.Errorf("Failed to create wallet address manager: %s\n", err)
			return err
		}

		err = wtxmgr.Create(txmgrNs)
		if err != nil {
			l.Errorf("Failed to create wallet transaction manager: %s\n", err)
			return err
		}

		return nil
	})

	c.db = db

	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	// Before attempting to open the wallet, we'll check if there are any
	// database upgrades for us to proceed. We'll also create our references
	// to the address and transaction managers, as they are backed by the
	// database.
	err = walletdb.Update(c.db, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if addrMgrBucket == nil {
			l.Error("Missing address manager namespace")
			return errors.New("missing address manager namespace")
		}
		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			l.Error("Missing transaction manager namespace")
			return errors.New("missing transaction manager namespace")
		}

		addrMgr, err = waddrmgr.Open(addrMgrBucket, []byte(""), c.chainParams)
		if err != nil {
			l.Errorf("Failed to open address manager: %s\n", err)
			return err
		}
		txMgr, err = wtxmgr.Open(txMgrBucket, c.chainParams)
		if err != nil {
			l.Errorf("Failed to open transaction manager: %s\n", err)
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	log.L(c.ctx).Infof("Opened wallet") // TODO: log balance? last sync height?
	c.Manager = addrMgr
	c.TxStore = txMgr
	return nil
}

// quitChan atomically reads the quit channel.
func (c *RPCClient) quitChan() <-chan struct{} {
	c.quitMtx.Lock()
	channel := c.quit
	c.quitMtx.Unlock()
	return channel
}

// SetChainSynced marks whether the wallet is connected to and currently in sync
// with the latest block notified by the chain server.
//
// NOTE: Due to an API limitation with rpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (c *RPCClient) SetChainSynced(synced bool) {
	c.chainClientSyncMtx.Lock()
	c.chainClientSynced = synced
	c.chainClientSyncMtx.Unlock()
}

// ChainSynced returns whether the wallet has been attached to a chain server
// and synced up to the best block on the main chain.
func (c *RPCClient) ChainSynced() bool {
	c.chainClientSyncMtx.Lock()
	synced := c.chainClientSynced
	c.chainClientSyncMtx.Unlock()
	return synced
}

func (r *RPCClient) Invoke(ctx context.Context, result interface{}, method string, params ...interface{}) error {
	id := atomic.AddUint64(&r.nextRPCRequestID, 1)
	rpcReq := &RPCRequest{
		JSONRpc: "2.0",
		ID:      fmt.Sprintf(`%d`, id),
		Method:  method,
		Params:  params,
	}
	var rpcRes RPCResponse

	log.L(ctx).Infof("RPC[%s] --> %s", rpcReq.ID, rpcReq.Method)
	res, err := r.httpClient.R().
		EnableTrace().
		SetContext(ctx).
		SetBody(rpcReq).
		SetResult(&rpcRes).
		SetError(&rpcRes).
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
	return json.Unmarshal(rpcRes.Result, result)
}

// IsCurrent returns whether the chain backend considers its view of the network
// as "current".
func (c *RPCClient) IsCurrent() bool {
	bestHash, _, err := c.GetBestBlock()
	if err != nil {
		return false
	}
	bestHeader, err := c.GetBlockHeader(bestHash)
	if err != nil {
		return false
	}
	return bestHeader.Timestamp.After(time.Now().Add(-isCurrentDelta))
}

func (c *RPCClient) BackendVersion() (rpcclient.BackendVersion, error) {
	c.backendVersionMu.Lock()
	defer c.backendVersionMu.Unlock()

	if c.backendVersion != nil {
		return *c.backendVersion, nil
	}

	// We'll start by calling GetInfo. This method doesn't exist for
	// bitcoind nodes as of v0.16.0, so we'll assume the client is connected
	// to a btcd backend if it does exist.
	info, err := c.GetInfo()

	switch err := err.(type) {
	// Parse the btcd version and cache it.
	case nil:
		log.L(c.ctx).Debugf("Detected btcd version: %v", info.Version)
		version := rpcclient.Btcd
		c.backendVersion = &version
		return *c.backendVersion, nil

	// Inspect the RPC error to ensure the method was not found, otherwise
	// we actually ran into an error.
	case *btcjson.RPCError:
		if err.Code != btcjson.ErrRPCMethodNotFound.Code {
			return 0, fmt.Errorf("unable to detect btcd version: "+
				"%v", err)
		}

	default:
		return 0, fmt.Errorf("unable to detect btcd version: %v", err)
	}

	// Since the GetInfo method was not found, we assume the client is
	// connected to a bitcoind backend, which exposes its version through
	// GetNetworkInfo.
	networkInfo, err := c.GetNetworkInfo()
	if err != nil {
		return 0, fmt.Errorf("unable to detect bitcoind version: %v", err)
	}

	// Parse the bitcoind version and cache it.
	log.L(c.ctx).Debugf("Detected bitcoind version: %v", networkInfo.SubVersion)
	version := parseBitcoindVersion(networkInfo.SubVersion)
	c.backendVersion = &version

	return *c.backendVersion, nil
}

// Notifications returns a channel of parsed notifications sent by the remote
// bitcoin RPC server.  This channel must be continually read or the process
// may abort for running out memory, as unread notifications are queued for
// later reads.
func (c *RPCClient) Notifications() <-chan interface{} {
	return c.dequeueNotification
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *RPCClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-c.currentBlock:
		return bs, nil
	case <-c.quit:
		return nil, errors.New("disconnected")
	}
}

// parseBlock parses a btcws definition of the block a tx is mined it to the
// Block structure of the wtxmgr package, and the block index.  This is done
// here since rpcclient doesn't parse this nicely for us.
func parseBlock(block *btcjson.BlockDetails) (*wtxmgr.BlockMeta, error) {
	if block == nil {
		return nil, nil
	}
	blkHash, err := chainhash.NewHashFromStr(block.Hash)
	if err != nil {
		return nil, err
	}
	blk := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Height: block.Height,
			Hash:   *blkHash,
		},
		Time: time.Unix(block.Time, 0),
	}
	return blk, nil
}

func (c *RPCClient) onClientConnect() {
	select {
	case c.enqueueNotification <- chain.ClientConnected{}:
	case <-c.quit:
	}
}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *RPCClient) handler() {
	l := log.L(c.ctx)
	hash, height, err := c.GetBestBlock()
	if err != nil {
		l.Errorf("Failed to receive best block from chain server: %v", err)
		c.Stop()
		c.wg.Done()
		return
	}

	bs := &waddrmgr.BlockStamp{Hash: *hash, Height: height}

	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed.  For example,
	// blockconnected notifications for greater block heights can remove the
	// need to process earlier blockconnected notifications still waiting
	// here.

	var notifications []interface{}
	enqueue := c.enqueueNotification
	var dequeue chan interface{}
	var next interface{}
out:
	for {
		select {
		case n, ok := <-enqueue:
			l.Tracef("Notification read from input queue: %+v\n", n)
			if !ok {
				// If no notifications are queued for handling,
				// the queue is finished.
				if len(notifications) == 0 {
					break out
				}
				// nil channel so no more reads can occur.
				enqueue = nil
				continue
			}
			if len(notifications) == 0 {
				next = n
				dequeue = c.dequeueNotification
			}
			notifications = append(notifications, n)

		case dequeue <- next:
			l.Tracef("Next notification sent to output queue: %+v\n", next)
			if n, ok := next.(chain.BlockConnected); ok {
				bs = &waddrmgr.BlockStamp{
					Height: n.Height,
					Hash:   n.Hash,
				}
			}

			notifications[0] = nil
			notifications = notifications[1:]
			if len(notifications) != 0 {
				next = notifications[0]
			} else {
				// If no more notifications can be enqueued, the
				// queue is finished.
				if enqueue == nil {
					break out
				}
				dequeue = nil
			}

		case c.currentBlock <- bs:
			l.Tracef("BlockStamp sent to currentBlock channel: %+v", bs)
		case <-c.quit:
			break out
		}
	}

	c.Stop()
	close(c.dequeueNotification)
	c.wg.Done()
}

// inMessage is the first type that an incoming message is unmarshaled
// into. It supports both requests (for notification support) and
// responses.  The partially-unmarshaled message is a notification if
// the embedded ID (from the response) is nil.  Otherwise, it is a
// response.
type inMessage struct {
	ID *float64 `json:"id"`
	*rawNotification
	*rawResponse
}

// rawNotification is a partially-unmarshaled JSON-RPC notification.
type rawNotification struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// rawResponse is a partially-unmarshaled JSON-RPC response.  For this
// to be valid (according to JSON-RPC 1.0 spec), ID may not be nil.
type rawResponse struct {
	Result json.RawMessage   `json:"result"`
	Error  *btcjson.RPCError `json:"error"`
}

// result checks whether the unmarshaled response contains a non-nil error,
// returning an unmarshaled btcjson.RPCError (or an unmarshaling error) if so.
// If the response is not an error, the raw bytes of the request are
// returned for further unmashaling into specific result types.
func (r rawResponse) result() (result []byte, err error) {
	if r.Error != nil {
		return nil, r.Error
	}
	return r.Result, nil
}

func (c *RPCClient) handleMessage(msg []byte) {
	// Attempt to unmarshal the message as either a notification or
	// response.
	l := log.L(c.ctx)
	var in inMessage
	in.rawResponse = new(rawResponse)
	in.rawNotification = new(rawNotification)
	err := json.Unmarshal(msg, &in)
	if err != nil {
		l.Warnf("Remote server sent invalid message: %v", err)
		return
	}

	// JSON-RPC 1.0 notifications are requests with a null id.
	if in.ID == nil {
		ntfn := in.rawNotification
		if ntfn == nil {
			l.Warn("Malformed notification: missing " +
				"method and parameters")
			return
		}
		if ntfn.Method == "" {
			l.Warn("Malformed notification: missing method")
			return
		}
		// params are not optional: nil isn't valid (but len == 0 is)
		if ntfn.Params == nil {
			l.Warn("Malformed notification: missing params")
			return
		}
		// Deliver the notification.
		c.handleNotification(in.rawNotification)
		return
	}

	// ensure that in.ID can be converted to an integer without loss of precision
	if *in.ID < 0 || *in.ID != math.Trunc(*in.ID) {
		l.Warn("Malformed response: invalid identifier")
		return
	}

	if in.rawResponse == nil {
		l.Warn("Malformed response: missing result and error")
		return
	}

	id := uint64(*in.ID)
	l.Tracef("Received response for id %d (result %s)", id, in.Result)
	request := c.removeRequest(id)

	// Nothing more to do if there is no request associated with this reply.
	if request == nil || request.responseChan == nil {
		l.Warnf("Received unexpected reply: %s (id %d)", in.Result,
			id)
		return
	}

	// Deliver the response.
	result, err := in.rawResponse.result()
	request.responseChan <- &Response{result: result, err: err}
}

// removeRequest returns and removes the jsonRequest which contains the response
// channel and original method associated with the passed id or nil if there is
// no association.
//
// This function is safe for concurrent access.
func (c *RPCClient) removeRequest(id uint64) *jsonRequest {
	c.requestLock.Lock()
	defer c.requestLock.Unlock()

	element := c.requestMap[id]
	if element != nil {
		delete(c.requestMap, id)
		request := c.requestList.Remove(element).(*jsonRequest)
		return request
	}

	return nil
}

const (
	// bitcoind19Str is the string representation of bitcoind v0.19.0.
	bitcoind19Str = "0.19.0"

	// bitcoindVersionPrefix specifies the prefix included in every bitcoind
	// version exposed through GetNetworkInfo.
	bitcoindVersionPrefix = "/Satoshi:"

	// bitcoindVersionSuffix specifies the suffix included in every bitcoind
	// version exposed through GetNetworkInfo.
	bitcoindVersionSuffix = "/"
)

// parseBitcoindVersion parses the bitcoind version from its string
// representation.
func parseBitcoindVersion(version string) rpcclient.BackendVersion {
	// Trim the version of its prefix and suffix to determine the
	// appropriate version number.
	version = strings.TrimPrefix(
		strings.TrimSuffix(version, bitcoindVersionSuffix),
		bitcoindVersionPrefix,
	)
	switch {
	case version < bitcoind19Str:
		return rpcclient.BitcoindPre19
	default:
		return rpcclient.BitcoindPost19
	}
}

// wsInHandler handles all incoming messages for the websocket connection
// associated with the client.  It must be run as a goroutine.
func (c *RPCClient) wsInHandler() {
out:
	for {
		// Break out of the loop once the shutdown channel has been
		// closed.  Use a non-blocking select here so we fall through
		// otherwise.
		select {
		case <-c.shutdown:
			break out
		default:
		}

		_, msg, err := c.wsClient.ReadMessage()
		if err != nil {
			log.L(c.ctx).Errorf("Websocket receive error: %v", err)
			break out
		}
		c.handleMessage(msg)
	}

	// Ensure the connection is closed.
	c.Disconnect()
	c.wg.Done()
	log.L(c.ctx).Trace("RPC client input handler done")
}

// wsOutHandler handles all outgoing messages for the websocket connection.  It
// uses a buffered channel to serialize output messages while allowing the
// sender to continue running asynchronously.  It must be run as a goroutine.
func (c *RPCClient) wsOutHandler() {
out:
	for {
		// Send any messages ready for send until the client is
		// disconnected closed.
		select {
		case msg := <-c.sendChan:
			err := c.wsClient.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				c.Disconnect()
				break out
			}

		case <-c.disconnectChan():
			break out
		}
	}

	// Drain any channels before exiting so nothing is left waiting around
	// to send.
cleanup:
	for {
		select {
		case <-c.sendChan:
		default:
			break cleanup
		}
	}
	c.wg.Done()
	log.L(c.ctx).Trace("RPC client output handler done")
}

// Disconnect disconnects the current websocket associated with the client.  The
// connection will automatically be re-established unless the client was
// created with the DisableAutoReconnect flag.
//
// This function has no effect when the client is running in HTTP POST mode.
func (c *RPCClient) Disconnect() {
	// Nothing to do if already disconnected or running in HTTP POST mode.
	if !c.doDisconnect() {
		return
	}

	c.requestLock.Lock()
	defer c.requestLock.Unlock()

	for e := c.requestList.Front(); e != nil; e = e.Next() {
		req := e.Value.(*jsonRequest)
		req.responseChan <- &Response{
			result: nil,
			err:    ErrClientDisconnect,
		}
	}
	c.removeAllRequests()
	c.doShutdown()
}

// doDisconnect disconnects the websocket associated with the client if it
// hasn't already been disconnected.  It will return false if the disconnect is
// not needed or the client is running in HTTP POST mode.
//
// This function is safe for concurrent access.
func (c *RPCClient) doDisconnect() bool {
	if c.wsClient == nil {
		return false
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Nothing to do if already disconnected.
	if c.disconnected {
		return false
	}

	log.L(c.ctx).Trace("Disconnecting RPC client")
	close(c.disconnect)
	if c.wsClient != nil {
		c.wsClient.Close()
	}
	c.disconnected = true
	return true
}

// doShutdown closes the shutdown channel and logs the shutdown unless shutdown
// is already in progress.  It will return false if the shutdown is not needed.
//
// This function is safe for concurrent access.
func (c *RPCClient) doShutdown() bool {
	// Ignore the shutdown request if the client is already in the process
	// of shutting down or already shutdown.
	select {
	case <-c.shutdown:
		return false
	default:
	}

	log.L(c.ctx).Trace("Shutting down RPC client")
	close(c.shutdown)
	return true
}

// removeAllRequests removes all the jsonRequests which contain the response
// channels for outstanding requests.
//
// This function MUST be called with the request lock held.
func (c *RPCClient) removeAllRequests() {
	c.requestMap = make(map[uint64]*list.Element)
	c.requestList.Init()
}
