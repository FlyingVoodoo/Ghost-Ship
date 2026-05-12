// Ghost-Ship Streamer Tests

#include "streamer.hpp"
#include <iostream>
#include <cassert>
#include <string>
#include <vector>

void test_oneshot_roundtrip() {
    std::cout << "Test 1: One-shot roundtrip... ";
    
    std::string original_msg = "Hello, Ghost-Ship!";
    std::vector<uint8_t> plaintext(original_msg.begin(), original_msg.end());
    
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i + 42;
    for (int i = 0; i < 12; ++i) nonce[i] = i + 123;
    
    Streamer streamer(key);
    auto encrypted = streamer.compress_encrypt(plaintext, nonce);
    assert(encrypted.is_ok());
    
    auto decrypted = streamer.decrypt_decompress(encrypted.cspan());
    assert(decrypted.is_ok());
    assert(decrypted.size() == plaintext.size());
    assert(std::equal(decrypted.data(), decrypted.data() + decrypted.size(), plaintext.begin()));
    
    std::cout << "PASS" << std::endl;
}

void test_streaming_api() {
    std::cout << "Test 2: Streaming encryption... ";
    
    std::vector<uint8_t> plaintext(10 * 1024);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = (i * 7 + 13) & 0xFF;
    }
    
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 32; ++i) key[i] = i + 42;
    for (int i = 0; i < 12; ++i) nonce[i] = i + 123;
    
    Streamer streamer(key);
    streamer.encrypt_begin(nonce);
    
    size_t chunk_size = 1024;
    for (size_t pos = 0; pos < plaintext.size(); pos += chunk_size) {
        size_t end = std::min(pos + chunk_size, plaintext.size());
        streamer.encrypt_update(std::span<const uint8_t>(
            plaintext.data() + pos, end - pos
        ));
    }
    
    auto encrypted = streamer.encrypt_final();
    assert(encrypted.is_ok());
    assert(encrypted.size() > 0);
    assert(encrypted.size() < plaintext.size() + 100);
    
    std::cout << "PASS" << std::endl;
}

void test_key_derivation() {
    std::cout << "Test 3: Key derivation... ";
    
    std::string passphrase = "mysecurepassword";
    auto salt1 = KeyDeriver::generate_salt(16);
    
    uint8_t key1[32];
    uint8_t key2[32];
    
    int ret1 = KeyDeriver::derive_pbkdf2(passphrase, salt1, key1);
    int ret2 = KeyDeriver::derive_pbkdf2(passphrase, salt1, key2);
    
    assert(ret1 == 0 && ret2 == 0);
    assert(std::equal(key1, key1 + 32, key2));
    
    uint8_t key3[32];
    KeyDeriver::derive_pbkdf2("different", salt1, key3);
    assert(!std::equal(key1, key1 + 32, key3));
    
    std::cout << "PASS" << std::endl;
}

void test_error_handling() {
    std::cout << "Test 4: Error handling... ";
    
    std::array<uint8_t, 32> key;
    for (int i = 0; i < 32; ++i) key[i] = i;
    
    Streamer streamer(key);
    std::vector<uint8_t> bad_input(10);
    auto result = streamer.decrypt_decompress(bad_input);
    assert(!result.is_ok());
    assert(result.error_code() != 0);
    assert(result.error_message().size() > 0);
    
    std::cout << "PASS" << std::endl;
}

void test_move_semantics() {
    std::cout << "Test 5: Move semantics... ";
    
    std::array<uint8_t, 32> key;
    for (int i = 0; i < 32; ++i) key[i] = i;
    
    Streamer s1(key);
    Streamer s2 = std::move(s1);
    
    std::vector<uint8_t> data(100, 42);
    std::array<uint8_t, 12> nonce;
    for (int i = 0; i < 12; ++i) nonce[i] = i;
    
    auto result = s2.compress_encrypt(data, nonce);
    assert(result.is_ok());
    
    {
        ByteResult r1 = std::move(result);
        assert(r1.is_ok());
    }
    
    std::cout << "PASS" << std::endl;
}

int main() {
    std::cout << "========================================\n"
              << "Ghost-Ship Streamer Tests (C++20 API)\n"
              << "========================================\n" << std::endl;
    
    try {
        test_oneshot_roundtrip();
        test_streaming_api();
        test_key_derivation();
        test_error_handling();
        test_move_semantics();
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "All tests PASSED!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
