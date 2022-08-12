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
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffresty"
)

const (
	ConfigGasEstimationFactor = "gasEstimationFactor"
	ConfigDataFormat          = "dataFormat"
)

const (
	DefaultListenerPort        = 5102
	DefaultGasEstimationFactor = 1.5
)

func InitConfig(conf config.Section) {
	ffresty.InitConfig(conf)

	conf.AddKnownKey(ConfigGasEstimationFactor, DefaultGasEstimationFactor)
	conf.AddKnownKey(ConfigDataFormat, "map")
	conf.AddKnownKey("auth.bearerToken")
	conf.AddKnownKey("auth.basicToken")
	conf.AddKnownKey("network")
	conf.AddKnownKey("ws.readBufferSize")
	conf.AddKnownKey("ws.writeBufferSize")
	conf.AddKnownKey("ws.initialConnectAttempts")
	conf.AddKnownKey("ws.heartbeatInterval")
	conf.AddKnownKey("ws.path")
	conf.AddKnownKey("ws.tls.enabled")
	conf.AddKnownKey("ws.tls.certificates")
}
