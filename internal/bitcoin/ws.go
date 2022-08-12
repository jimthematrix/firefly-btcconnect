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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
)

var (
	// ErrInvalidAuth is an error to describe the condition where the client
	// is either unable to authenticate or the specified endpoint is
	// incorrect.
	ErrInvalidAuth = errors.New("authentication failure")

	// ErrInvalidEndpoint is an error to describe the condition where the
	// websocket handshake failed with the specified endpoint.
	ErrInvalidEndpoint = errors.New("the endpoint either does not support websockets or does not exist")
)

const (
	// connectionRetryInterval is the amount of time to wait in between
	// retries when automatically reconnecting to an RPC server.
	connectionRetryInterval = time.Second * 5
)

// Connect establishes the initial websocket connection.  This is necessary when
// a client was created after setting the DisableConnectOnNew field of the
// Config struct.
//
// Up to tries number of connections (each after an increasing backoff) will
// be tried if the connection can not be established.  The special value of 0
// indicates an unlimited number of connection attempts.
//
// This method will error if the client is not configured for websockets, if the
// connection has already been established, or if none of the connection
// attempts were successful.
func newWSClient(ctx context.Context, config config.Section, basicToken, username, password string) (*websocket.Conn, error) {
	tries := config.GetInt(wsclient.WSConfigKeyInitialConnectAttempts)
	l := log.L(ctx)

	// Begin connection attempts.  Increase the backoff after each failed
	// attempt, up to a maximum of one minute.
	var err error
	var backoff time.Duration
	host := config.GetString(ffresty.HTTPConfigURL)
	for i := 0; tries == 0 || i < tries; i++ {
		var wsConn *websocket.Conn
		wsConn, err = dial(config, basicToken, username, password)
		if err != nil {
			l.Infof("Failed to dial %+v, %s", host, err)
			backoff = connectionRetryInterval * time.Duration(i+1)
			if backoff > time.Minute {
				backoff = time.Minute
			}
			time.Sleep(backoff)
			continue
		}

		// Connection was established.  Set the websocket connection
		// member of the client and start the goroutines necessary
		// to run the client.
		l.Infof("Established connection to RPC server %s", host)
		return wsConn, nil
	}

	// All connection attempts failed, so return the last error.
	return nil, err
}

// dial opens a websocket connection using the passed connection configuration
// details.
func dial(config config.Section, basicToken, username, password string) (*websocket.Conn, error) {
	// Setup TLS if not disabled.
	var tlsConfig *tls.Config
	var scheme = "ws"
	if config.GetBool("ws.tls.enabled") {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if len(config.GetString("ws.tls.certificates")) > 0 {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(config.GetString("ws.tls.certificates")))
			tlsConfig.RootCAs = pool
		}
		scheme = "wss"
	}

	// Create a websocket dialer that will be used to make the connection.
	// It is modified by the proxy setting below as needed.
	dialer := websocket.Dialer{TLSClientConfig: tlsConfig}

	// The RPC server requires basic authorization, so create a custom
	// request header with the Authorization header set.
	var auth string
	if basicToken != "" {
		auth = basicToken
	} else {
		login := username + ":" + password
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	}
	requestHeader := make(http.Header)
	requestHeader.Add("Authorization", auth)

	// Dial the connection.
	host := config.GetString(ffresty.HTTPConfigURL)
	exp1 := regexp.MustCompile(`(.+[^/])/?$`)
	host = exp1.ReplaceAllString(host, "$1")

	wspath := config.GetString(wsclient.WSConfigKeyPath)
	exp2 := regexp.MustCompile(`^/?(.+)`)
	wspath = exp2.ReplaceAllString(wspath, "$1")
	url := fmt.Sprintf("%s://%s/%s", scheme, host, wspath)
	fmt.Printf("==== url: %s\n", url)
	wsConn, resp, err := dialer.Dial(url, requestHeader)
	if err != nil {
		if err != websocket.ErrBadHandshake || resp == nil {
			return nil, err
		}

		// Detect HTTP authentication error status codes.
		if resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden {
			return nil, ErrInvalidAuth
		}

		// The connection was authenticated and the status response was
		// ok, but the websocket handshake still failed, so the endpoint
		// is invalid in some way.
		if resp.StatusCode == http.StatusOK {
			return nil, ErrInvalidEndpoint
		}

		// Return the status text from the server if none of the special
		// cases above apply.
		return nil, errors.New(resp.Status)
	}
	return wsConn, nil
}
