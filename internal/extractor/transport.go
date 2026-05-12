package extractor

/*
#cgo CXXFLAGS: -std=c++20 -I${SRCDIR}/../../clib
#cgo LDFLAGS: -L${SRCDIR}/../../clib -lstreamer -llz4 -lssl -lcrypto
#include "streamer.hpp"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func CompressAndEncrypt(data []byte, key [32]byte, nonce[12]byte) ([]byte, error) {
	srcPtr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	srcLen := C.size_t(len(data))
	keyPtr := (*C.uint8_t)(unsafe.Pointer(&key[0]))
	noncePtr := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))

	result := C.compress_and_encrypt(srcPtr, srcLen, keyPtr, noncePtr)

	defer C.free(unsafe.Pointer(&result))

	if result.len == 0 {
		return nil, fmt.Errorf("C++ error: %s", C.GoString(&result.error_msg[0]))
	}

	compressedData := C.GoBytes(unsafe.Pointer(result.data), C.int(result.len))
	return compressedData, nil
}