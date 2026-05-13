package extractor

/*
#cgo CXXFLAGS: -std=c++20 -fPIC
#cgo LDFLAGS: -L/run/media/flyingvoodoo/New_Volume/projects/Ghost-Ship/clib/build/lib -lstreamer -llz4 -lssl -lcrypto -lstdc++
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t* data;
    size_t len;
    int error;
    char error_msg[256];
} StreamerResult_C;

extern StreamerResult_C streamer_compress_encrypt(const uint8_t* src, size_t src_len, const uint8_t* key, const uint8_t* nonce);
extern void streamer_free(StreamerResult_C* r);
*/
import "C"

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
	"gopkg.in/yaml.v3"
)

// StreamState packs SystemState into secure stream with LZ4+AES-256 encryption
type StreamState struct {
	Data     []byte
	Key      [32]byte
	Nonce    [12]byte
	Checksum string
	Size     int64
}

func CompressAndEncrypt(data []byte, key [32]byte, nonce [12]byte) ([]byte, error) {
	srcPtr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	srcLen := C.size_t(len(data))
	keyPtr := (*C.uint8_t)(unsafe.Pointer(&key[0]))
	noncePtr := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))

	result := C.streamer_compress_encrypt(srcPtr, srcLen, keyPtr, noncePtr)
	defer C.streamer_free(&result)

	if result.error != 0 {
		return nil, fmt.Errorf("C++ error: %s", C.GoString(&result.error_msg[0]))
	}

	if result.len == 0 {
		return nil, fmt.Errorf("compression resulted in zero bytes")
	}

	compressedData := C.GoBytes(unsafe.Pointer(result.data), C.int(result.len))
	return compressedData, nil
}

// PackSystemState packages SystemState into TAR archive and encrypts
func PackSystemState(state *SystemState) (*StreamState, error) {
	slog.Info("packing system state for transmission")

	// Create TAR archive in memory
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	defer tw.Close()

	// Add YAML state metadata
	metadata, err := yaml.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state: %w", err)
	}

	hdr := &tar.Header{
		Name: "STATE.yaml",
		Mode: 0644,
		Size: int64(len(metadata)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := tw.Write(metadata); err != nil {
		return nil, fmt.Errorf("failed to write state metadata: %w", err)
	}

	// Add certificates
	for name, data := range state.Certificates {
		hdr := &tar.Header{
			Name: fmt.Sprintf("certs/%s", name),
			Mode: 0600,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			slog.Warn("failed to write cert header", "name", name)
			continue
		}
		if _, err := tw.Write(data); err != nil {
			slog.Warn("failed to write cert data", "name", name)
		}
	}

	// Add databases
	for name, data := range state.Databases {
		hdr := &tar.Header{
			Name: fmt.Sprintf("databases/%s", name),
			Mode: 0600,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			slog.Warn("failed to write database header", "name", name)
			continue
		}
		if _, err := tw.Write(data); err != nil {
			slog.Warn("failed to write database data", "name", name)
		}
	}

	// Add configurations
	for name, data := range state.Configs {
		hdr := &tar.Header{
			Name: fmt.Sprintf("configs/%s", name),
			Mode: 0600,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			slog.Warn("failed to write config header", "name", name)
			continue
		}
		if _, err := tw.Write(data); err != nil {
			slog.Warn("failed to write config data", "name", name)
		}
	}

	// Add SSH public keys
	for name, data := range state.SSHPublicKeys {
		hdr := &tar.Header{
			Name: fmt.Sprintf("ssh_keys/%s", name),
			Mode: 0644,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			slog.Warn("failed to write ssh key header", "name", name)
			continue
		}
		if _, err := tw.Write(data); err != nil {
			slog.Warn("failed to write ssh key data", "name", name)
		}
	}

	tarData := buf.Bytes()
	slog.Info("tar archive created", "size_mb", float64(len(tarData))/1024/1024)

	// Generate encryption key and nonce
	var key [32]byte
	var nonce [12]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Compress and encrypt via C++
	encrypted, err := CompressAndEncrypt(tarData, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("compression/encryption failed: %w", err)
	}

	slog.Info("state packed and encrypted",
		"original_size_mb", float64(len(tarData))/1024/1024,
		"encrypted_size_mb", float64(len(encrypted))/1024/1024,
		"compression_ratio", float64(len(encrypted))/float64(len(tarData)),
	)

	return &StreamState{
		Data:  encrypted,
		Key:   key,
		Nonce: nonce,
		Size:  int64(len(tarData)),
	}, nil
}

// UnpackSystemState unpacks encrypted stream back to SystemState
func UnpackSystemState(stream *StreamState) (*SystemState, error) {
	slog.Info("unpacking system state from stream")

	// Decompression implementation pending: requires C++ inverse function
	slog.Warn("decompression not yet implemented - requires C++ inverse function")
	return nil, fmt.Errorf("unpacking requires C++ decompression support")
}

// TransmitState transmits encrypted stream to target server via SSH
func TransmitState(client *sshutil.SSHClient, stream *StreamState, targetPath string) error {
	slog.Info("transmitting state to target server",
		"target_path", targetPath,
		"size_mb", float64(len(stream.Data))/1024/1024,
	)

	// TODO: Implement chunked file transmission via SSH
	slog.Warn("transmission requires SCP/SFTP implementation")
	return fmt.Errorf("transmission not yet implemented")
}
