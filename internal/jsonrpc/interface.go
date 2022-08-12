package jsonrpc

import (
	"time"
)

// isCurrentDelta is the delta duration we'll use from the present time to
// determine if a backend is considered "current", i.e. synced to the tip of
// the chain.
const isCurrentDelta = 2 * time.Hour

type WsClient interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
}
