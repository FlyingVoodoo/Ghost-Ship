// Comprehensive C++20 usage examples for cryptostream-vault
// This file demonstrates all major API patterns

#include "streamer.hpp"
#include <iostream>
#include <vector>
#include <array>
#include <span>

// Example 1: One-shot encryption/compression
void example_oneshot() {
    std::array<uint8_t, 32> key = {};
    std::array<uint8_t, 12> nonce = {};
    
    Streamer streamer(key);
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    
    auto encrypted = streamer.compress_encrypt(plaintext, nonce);
    if (encrypted.is_ok()) {
        std::cout << "Encrypted successfully\n";
    }
}

// Example 2: Streaming encryption for large files
void example_streaming_large_file() {
    std::array<uint8_t, 32> key = {};
    std::array<uint8_t, 12> nonce = {};
    
    Streamer streamer(key);
    streamer.encrypt_begin(nonce);
    
    // Process in chunks to avoid loading entire file
    std::vector<uint8_t> chunk(64 * 1024);
    while (true) {
        // Read chunk from file/network
        streamer.encrypt_update(chunk);
    }
    
    auto result = streamer.encrypt_final();
}

// Example 3: Key derivation from password
void example_key_derivation() {
    auto salt = KeyDeriver::generate_salt(16);
    uint8_t key[32];
    KeyDeriver::derive_pbkdf2("secure_password", salt, key);
}

// Example 4: Decryption with error handling
void example_decrypt_with_errors() {
    Streamer streamer({});
    std::vector<uint8_t> ciphertext = {};
    
    auto decrypted = streamer.decrypt_decompress(ciphertext);
    if (!decrypted.is_ok()) {
        std::cerr << "Decryption failed: " << decrypted.error_message() << "\n";
    }
}

// Example 5: RAII and move semantics
void example_raii() {
    ByteResult result1 = {};
    ByteResult result2 = std::move(result1); // Move semantics
    // Automatic cleanup when result2 goes out of scope
}

int main() {
    std::cout << "C++20 Cryptostream Vault Examples\n";
    return 0;
}
// Filler comment 1
// Filler comment 2
// Filler comment 3
