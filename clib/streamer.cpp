/**
 * Ghost-Ship :: C++ Secure Streamer (C++20 Edition)
 *
 * Pipeline: raw bytes -> LZ4 compress -> AES-256-GCM encrypt -> wire
 * Optimized single allocation, stateful API, streaming support.
 */

#include "streamer.hpp"

#include <cstring>
#include <cstdlib>
#include <memory>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <lz4.h>

namespace {

void write_u32_be(uint8_t* buf, uint32_t v) {
    buf[0] = (v >> 24) & 0xFF;
    buf[1] = (v >> 16) & 0xFF;
    buf[2] = (v >>  8) & 0xFF;
    buf[3] =  v        & 0xFF;
}

constexpr uint32_t read_u32_be(const uint8_t* buf) {
    return ((uint32_t)buf[0] << 24)
         | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] <<  8)
         |  (uint32_t)buf[3];
}

// LZ4 compression

std::vector<uint8_t> lz4_compress(std::span<const uint8_t> src) {
    int max_dst = LZ4_compressBound((int)src.size());
    std::vector<uint8_t> dst(4 + max_dst);
    
    write_u32_be(dst.data(), (uint32_t)src.size());
    
    int compressed = LZ4_compress_default(
        (const char*)src.data(),
        (char*)dst.data() + 4,
        (int)src.size(),
        max_dst
    );
    
    if (compressed <= 0) throw std::runtime_error("LZ4 compression failed");
    dst.resize(4 + compressed);
    return dst;
}

std::vector<uint8_t> lz4_decompress(std::span<const uint8_t> src) {
    if (src.size() < 4) throw std::runtime_error("LZ4: too short");
    
    uint32_t original_len = read_u32_be(src.data());
    if (original_len > Streamer::MAX_DATA_SIZE)
        throw std::runtime_error("LZ4: implausible original_len");
    
    std::vector<uint8_t> dst(original_len);
    int result = LZ4_decompress_safe(
        (const char*)src.data() + 4,
        (char*)dst.data(),
        (int)(src.size() - 4),
        (int)original_len
    );
    
    if (result < 0) throw std::runtime_error("LZ4 decompression failed");
    dst.resize(result);
    return dst;
}

// AES-256-GCM encryption/decryption

std::vector<uint8_t> aes_gcm_encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce
) {
    if (key.size() != 32) throw std::invalid_argument("key must be 32 bytes");
    if (nonce.size() != 12) throw std::invalid_argument("nonce must be 12 bytes");
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int len = 0, ciphertext_len = 0;

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            throw std::runtime_error("EVP_EncryptInit_ex (key/nonce) failed");
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate failed");
        ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        ciphertext_len += len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + ciphertext_len) != 1)
            throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len + 16);
    return ciphertext;
}

std::vector<uint8_t> aes_gcm_decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce
) {
    if (key.size() != 32) throw std::invalid_argument("key must be 32 bytes");
    if (nonce.size() != 12) throw std::invalid_argument("nonce must be 12 bytes");
    if (ciphertext.size() < 16) throw std::runtime_error("AES-GCM: ciphertext too short");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    size_t actual_ct_len = ciphertext.size() - 16;
    std::vector<uint8_t> plaintext(actual_ct_len);
    int len = 0, plaintext_len = 0;

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("EVP_DecryptInit_ex failed");
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            throw std::runtime_error("EVP_DecryptInit_ex (key/nonce) failed");
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)actual_ct_len) != 1)
            throw std::runtime_error("EVP_DecryptUpdate failed");
        plaintext_len = len;

        uint8_t* tag = const_cast<uint8_t*>(ciphertext.data() + actual_ct_len);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)
            throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        if (ret <= 0) throw std::runtime_error("AES-GCM: authentication tag mismatch — data corrupted or tampered");
        plaintext_len += len;
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}

} // namespace

// Streamer implementation (hidden Impl)

class Streamer::Impl {
public:
    std::vector<uint8_t> buffer;
    EVP_CIPHER_CTX* ctx = nullptr;
    
    Impl() {
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    
    ~Impl() {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
    
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;
};

// Streamer public API

Streamer::Streamer(std::span<const uint8_t, KEY_SIZE> key) 
    : m_impl(std::make_unique<Impl>()) 
{
    std::copy_n(key.begin(), KEY_SIZE, m_key.begin());
}

Streamer::~Streamer() = default;

Streamer::Streamer(Streamer&&) noexcept = default;
Streamer& Streamer::operator=(Streamer&&) noexcept = default;

ByteResult Streamer::compress_encrypt(
    std::span<const uint8_t> src,
    std::span<const uint8_t, NONCE_SIZE> nonce
) {
    try {
        auto compressed = lz4_compress(src);
        
        auto encrypted = aes_gcm_encrypt(compressed, m_key, nonce);
        
        size_t total = NONCE_SIZE + encrypted.size();
        uint8_t* out = static_cast<uint8_t*>(std::malloc(total));
        if (!out) return ByteResult(1, "malloc failed");

        std::copy_n(nonce.begin(), NONCE_SIZE, out);
        std::copy_n(encrypted.begin(), encrypted.size(), out + NONCE_SIZE);
        
        return ByteResult(out, total);
    } catch (const std::exception& e) {
        return ByteResult(1, e.what());
    }
}

ByteResult Streamer::decrypt_decompress(std::span<const uint8_t> src) {
    try {
        if (src.size() < NONCE_SIZE + TAG_SIZE)
            return ByteResult(1, "input too short");
        
        auto nonce = src.subspan<0, NONCE_SIZE>();
        auto ciphertext = src.subspan(NONCE_SIZE);
        
        auto compressed = aes_gcm_decrypt(ciphertext, m_key, nonce);
        auto plaintext = lz4_decompress(compressed);
        
        // OPTIMIZED: Single allocation
        uint8_t* out = static_cast<uint8_t*>(std::malloc(plaintext.size()));
        if (!out) return ByteResult(1, "malloc failed");
        
        std::copy_n(plaintext.begin(), plaintext.size(), out);
        return ByteResult(out, plaintext.size());
    } catch (const std::exception& e) {
        return ByteResult(1, e.what());
    }
}

void Streamer::encrypt_begin(std::span<const uint8_t, NONCE_SIZE> nonce) {
    if (EVP_EncryptInit_ex(m_impl->ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    if (EVP_CIPHER_CTX_ctrl(m_impl->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    if (EVP_EncryptInit_ex(m_impl->ctx, nullptr, nullptr, m_key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex (key/nonce) failed");
    
    m_impl->buffer.clear();
}

void Streamer::encrypt_update(std::span<const uint8_t> chunk) {
    int len = 0;
    std::vector<uint8_t> out(chunk.size() + 16);
    if (EVP_EncryptUpdate(m_impl->ctx, out.data(), &len, chunk.data(), (int)chunk.size()) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");
    out.resize(len);
    m_impl->buffer.insert(m_impl->buffer.end(), out.begin(), out.end());
}

ByteResult Streamer::encrypt_final() {
    try {
        std::vector<uint8_t> out(16 + 16);
        int len = 0;
        if (EVP_EncryptFinal_ex(m_impl->ctx, out.data(), &len) != 1)
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        out.resize(len);
        m_impl->buffer.insert(m_impl->buffer.end(), out.begin(), out.end());
        
        // Get tag
        std::vector<uint8_t> tag(TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(m_impl->ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
            throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
        m_impl->buffer.insert(m_impl->buffer.end(), tag.begin(), tag.end());
        
        uint8_t* out_buf = static_cast<uint8_t*>(std::malloc(m_impl->buffer.size()));
        if (!out_buf) throw std::runtime_error("malloc failed");
        std::copy_n(m_impl->buffer.begin(), m_impl->buffer.size(), out_buf);
        
        return ByteResult(out_buf, m_impl->buffer.size());
    } catch (const std::exception& e) {
        return ByteResult(1, e.what());
    }
}

void Streamer::decrypt_begin() {
    if (EVP_DecryptInit_ex(m_impl->ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    if (EVP_CIPHER_CTX_ctrl(m_impl->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    m_impl->buffer.clear();
}

void Streamer::decrypt_update(std::span<const uint8_t> chunk) {
    int len = 0;
    std::vector<uint8_t> out(chunk.size() + 16);
    if (EVP_DecryptUpdate(m_impl->ctx, out.data(), &len, chunk.data(), (int)chunk.size()) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");
    out.resize(len);
    m_impl->buffer.insert(m_impl->buffer.end(), out.begin(), out.end());
}

ByteResult Streamer::decrypt_final() {
    try {
        std::vector<uint8_t> out(16);
        int len = 0;
        int ret = EVP_DecryptFinal_ex(m_impl->ctx, out.data(), &len);
        if (ret <= 0) throw std::runtime_error("AES-GCM: authentication failed");
        out.resize(len);
        m_impl->buffer.insert(m_impl->buffer.end(), out.begin(), out.end());
        
        uint8_t* out_buf = static_cast<uint8_t*>(std::malloc(m_impl->buffer.size()));
        if (!out_buf) throw std::runtime_error("malloc failed");
        std::copy_n(m_impl->buffer.begin(), m_impl->buffer.size(), out_buf);
        
        return ByteResult(out_buf, m_impl->buffer.size());
    } catch (const std::exception& e) {
        return ByteResult(1, e.what());
    }
}

// KeyDeriver implementation

int KeyDeriver::derive_pbkdf2(
    std::string_view passphrase,
    std::span<const uint8_t> salt,
    uint8_t* out_key
) {
    int ret = PKCS5_PBKDF2_HMAC(
        passphrase.data(), (int)passphrase.size(),
        salt.data(), (int)salt.size(),
        100000,
        EVP_sha256(),
        32, out_key
    );
    return (ret == 1) ? 0 : -1;
}

std::vector<uint8_t> KeyDeriver::generate_salt(size_t len) {
    std::vector<uint8_t> salt(len);
    if (RAND_bytes(salt.data(), (int)len) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return salt;
}

// C API wrapper (backwards compatibility)

extern "C" {

StreamerResult_C streamer_compress_encrypt(
    const uint8_t* src,
    size_t         src_len,
    const uint8_t* key,
    const uint8_t* nonce
) {
    try {
        std::array<uint8_t, 32> key_arr;
        std::array<uint8_t, 12> nonce_arr;
        std::copy_n(key, 32, key_arr.begin());
        std::copy_n(nonce, 12, nonce_arr.begin());
        
        Streamer streamer(key_arr);
        auto result = streamer.compress_encrypt(
            std::span<const uint8_t>(src, src_len),
            nonce_arr
        );
        
        StreamerResult_C res{};
        if (result.is_ok()) {
            res.data = result.data();
            res.len = result.size();
        } else {
            res.error = result.error_code();
            std::copy_n(result.error_message().begin(), 
                       std::min(result.error_message().size(), sizeof(res.error_msg) - 1),
                       res.error_msg);
        }
        return res;
    } catch (const std::exception& e) {
        StreamerResult_C res{};
        res.error = 1;
        strncpy(res.error_msg, e.what(), sizeof(res.error_msg) - 1);
        return res;
    }
}

StreamerResult_C streamer_decrypt_decompress(
    const uint8_t* src,
    size_t         src_len,
    const uint8_t* key
) {
    try {
        std::array<uint8_t, 32> key_arr;
        std::copy_n(key, 32, key_arr.begin());
        
        Streamer streamer(key_arr);
        auto result = streamer.decrypt_decompress(
            std::span<const uint8_t>(src, src_len)
        );
        
        StreamerResult_C res{};
        if (result.is_ok()) {
            res.data = result.data();
            res.len = result.size();
        } else {
            res.error = result.error_code();
            std::copy_n(result.error_message().begin(),
                       std::min(result.error_message().size(), sizeof(res.error_msg) - 1),
                       res.error_msg);
        }
        return res;
    } catch (const std::exception& e) {
        StreamerResult_C res{};
        res.error = 1;
        strncpy(res.error_msg, e.what(), sizeof(res.error_msg) - 1);
        return res;
    }
}

void streamer_free(StreamerResult_C* r) {
    if (r && r->data) {
        std::free(r->data);
        r->data = nullptr;
        r->len = 0;
    }
}

int streamer_derive_key(
    const char*    passphrase,
    const uint8_t* salt,
    size_t         salt_len,
    uint8_t*       out_key
) {
    return KeyDeriver::derive_pbkdf2(
        passphrase,
        std::span<const uint8_t>(salt, salt_len),
        out_key
    );
}

} // extern "C"