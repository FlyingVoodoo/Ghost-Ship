//go:build cgo_streamer

package extractor

/*
#cgo CXXFLAGS: -std=c++20 -fPIC
#cgo LDFLAGS: -L${SRCDIR}/../../clib/build/lib -lstreamer -llz4 -lssl -lcrypto -lstdc++
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t* data;
    size_t len;
    int error;
    char error_msg[256];
} StreamerResult_C;

extern StreamerResult_C streamer_compress_encrypt(const uint8_t* src, size_t src_len, const uint8_t* key, const uint8_t* nonce);
extern StreamerResult_C streamer_decrypt_decompress(const uint8_t* src, size_t src_len, const uint8_t* key);
extern void streamer_free(StreamerResult_C* r);
*/
import "C"

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"
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

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	defer tw.Close()

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

	addToTar := func(prefix string, data map[string][]byte) error {
		for name, content := range data {
			hdr := &tar.Header{
				Name: fmt.Sprintf("%s/%s", prefix, name),
				Mode: 0600,
				Size: int64(len(content)),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				slog.Warn("failed to write tar header", "prefix", prefix, "name", name)
				continue
			}
			if _, err := tw.Write(content); err != nil {
				slog.Warn("failed to write tar data", "prefix", prefix, "name", name)
			}
		}
		return nil
	}

	addToTar("certs", state.Certificates)
	addToTar("databases", state.Databases)
	addToTar("configs", state.Configs)

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

	var key [32]byte
	var nonce [12]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

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

	encryptedWithNonce := make([]byte, len(stream.Nonce)+len(stream.Data))
	copy(encryptedWithNonce, stream.Nonce[:])
	copy(encryptedWithNonce[len(stream.Nonce):], stream.Data)

	srcPtr := (*C.uint8_t)(unsafe.Pointer(&encryptedWithNonce[0]))
	srcLen := C.size_t(len(encryptedWithNonce))
	keyPtr := (*C.uint8_t)(unsafe.Pointer(&stream.Key[0]))

	result := C.streamer_decrypt_decompress(srcPtr, srcLen, keyPtr)
	defer C.streamer_free(&result)

	if result.error != 0 {
		return nil, fmt.Errorf("C++ decryption error: %s", C.GoString(&result.error_msg[0]))
	}

	if result.len == 0 {
		return nil, fmt.Errorf("decompressed data is empty")
	}

	tarData := C.GoBytes(unsafe.Pointer(result.data), C.int(result.len))
	tr := tar.NewReader(bytes.NewReader(tarData))

	state := &SystemState{
		Certificates:  make(map[string][]byte),
		Databases:     make(map[string][]byte),
		Configs:       make(map[string][]byte),
		SSHPublicKeys: make(map[string][]byte),
	}

	prefixMap := map[string]*map[string][]byte{
		"certs/":     &state.Certificates,
		"databases/": &state.Databases,
		"configs/":   &state.Configs,
		"ssh_keys/":  &state.SSHPublicKeys,
	}

	for {
		hdr, err := tr.Next()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("tar read error: %w", err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("failed to read tar entry %s: %w", hdr.Name, err)
		}

		if hdr.Name == "STATE.yaml" {
			if err := yaml.Unmarshal(data, state); err != nil {
				return nil, fmt.Errorf("failed to unmarshal state metadata: %w", err)
			}
			continue
		}

		for prefix, targetMap := range prefixMap {
			if strings.HasPrefix(hdr.Name, prefix) {
				name := strings.TrimPrefix(hdr.Name, prefix)
				(*targetMap)[name] = data
				break
			}
		}
	}

	slog.Info("state unpacked successfully",
		"databases", len(state.Databases),
		"certs", len(state.Certificates),
		"configs", len(state.Configs),
		"ssh_keys", len(state.SSHPublicKeys),
	)

	return state, nil
}

// TransmitState transmits encrypted stream to remote via SSH with base64 encoding
func TransmitState(client sshutil.SSHRunner, stream *StreamState, targetPath string) error {
	slog.Info("transmitting state to target server",
		"target_path", targetPath,
		"size_mb", float64(len(stream.Data))/1024/1024,
	)

	encryptedWithNonce := make([]byte, len(stream.Nonce)+len(stream.Data))
	copy(encryptedWithNonce, stream.Nonce[:])
	copy(encryptedWithNonce[len(stream.Nonce):], stream.Data)

	encoded := base64.StdEncoding.EncodeToString(encryptedWithNonce)
	decodeCmd := fmt.Sprintf("echo '%s' | base64 -d | sudo tee %s > /dev/null", encoded, targetPath)
	_, err := client.Run(decodeCmd)
	if err != nil {
		return fmt.Errorf("transmission failed: %w", err)
	}

	slog.Info("state transmitted successfully", "path", targetPath)
	return nil
}
