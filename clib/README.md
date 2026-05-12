# Ghost-Ship Streamer

C++20 library for fast encryption and compression. Uses AES-256-GCM + LZ4. Can handle big files without loading everything into memory.

## Requirements

- OpenSSL >= 1.1.1
- LZ4
- C++20 compiler (g++11+, clang13+)

## Build

```bash
cd clib && mkdir build && cd build
cmake ..
make
```

Tests:
```bash
./streamer_test
```

Benchmarks:
```bash
./streamer_bench
```

## Quick Example

```cpp
#include "streamer.hpp"

std::array<uint8_t, 32> key = { /* 32 bytes */ };
std::array<uint8_t, 12> nonce = { /* 12 bytes */ };

Streamer streamer(key);

// Encrypt + compress
std::vector<uint8_t> data = { /* your data */ };
auto result = streamer.compress_encrypt(data, nonce);

if (result.is_ok()) {
    // Send result.data() with size result.size()
} else {
    std::cerr << result.error_message() << std::endl;
}
```

Decrypt:
```cpp
auto result = streamer.decrypt_decompress(received_data);
```

For big files (streaming):
```cpp
streamer.encrypt_begin(nonce);
while (read_chunk(chunk)) {
    streamer.encrypt_update(chunk);
}
auto result = streamer.encrypt_final();
```

Key derivation from password:
```cpp
auto salt = KeyDeriver::generate_salt(16);
uint8_t key[32];
KeyDeriver::derive_pbkdf2("password", salt, key);
```

## Notes

**Constants:**
- Key: 32 bytes (AES-256)
- Nonce: 12 bytes (GCM)
- Tag: 16 bytes (auth)
- Max size: 256MB

**Security:**
- Each (key, nonce) pair must be unique
- PBKDF2 with 100k iterations
- Tag auto-verified in decryption
- Result is RAII: auto-cleanup on scope exit

**Threading:**
- Each `Streamer` instance for one thread
- Multiple instances are thread-safe
