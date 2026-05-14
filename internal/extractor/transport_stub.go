//go:build !cgo_streamer

package extractor

import (
	"fmt"
)

// StreamState is a lightweight representation used when the C++ streamer is
// disabled (e.g., in unit tests). The real implementation lives in the
// cgo-enabled file.
type StreamState struct {
	Data     []byte
	Key      [32]byte
	Nonce    [12]byte
	Checksum string
	Size     int64
}

// CompressAndEncrypt is a stub used during tests when cgo streamer is disabled.
func CompressAndEncrypt(data []byte, key [32]byte, nonce [12]byte) ([]byte, error) {
	return nil, fmt.Errorf("cgo streamer disabled")
}

// PackSystemState stub: returns an empty StreamState for tests.
func PackSystemState(state *SystemState) (*StreamState, error) {
	return &StreamState{Data: []byte{}}, nil
}
