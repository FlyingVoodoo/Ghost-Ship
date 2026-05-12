#pragma once

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <memory>
#include <stdexcept>
#include <array>
#include <concepts>
#include <span>
#include <string_view>

template<typename T>
class Result {
public:
    Result() : m_data(nullptr), m_len(0), m_error(0), m_error_msg{} {}
    
    explicit Result(int error, std::string_view msg) 
        : m_data(nullptr), m_len(0), m_error(error), m_error_msg{}
    {
        const size_t n = std::min(msg.size(), sizeof(m_error_msg) - 1);
        std::copy_n(msg.begin(), n, m_error_msg);
        m_error_msg[n] = '\0';
    }
    
    Result(T* data, size_t len) 
        : m_data(data), m_len(len), m_error(0), m_error_msg{} {}
    
    [[nodiscard]] bool is_ok() const { return m_error == 0; }
    [[nodiscard]] int error_code() const { return m_error; }
    [[nodiscard]] std::string_view error_message() const { return m_error_msg; }
    
    [[nodiscard]] T* data() { return m_data; }
    [[nodiscard]] const T* data() const { return m_data; }
    [[nodiscard]] size_t size() const { return m_len; }
    
    [[nodiscard]] std::span<T> span() { return std::span<T>(m_data, m_len); }
    [[nodiscard]] std::span<const T> cspan() const { return std::span<const T>(m_data, m_len); }
    
    void free() {
        if (m_data) {
            std::free(m_data);
            m_data = nullptr;
            m_len = 0;
        }
    }
    
    ~Result() { free(); }
    
    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;
    Result(Result&& other) noexcept 
        : m_data(other.m_data), m_len(other.m_len), m_error(other.m_error)
    {
        std::copy_n(other.m_error_msg, sizeof(m_error_msg), m_error_msg);
        other.m_data = nullptr;
        other.m_len = 0;
    }
    Result& operator=(Result&& other) noexcept {
        free();
        m_data = other.m_data;
        m_len = other.m_len;
        m_error = other.m_error;
        std::copy_n(other.m_error_msg, sizeof(m_error_msg), m_error_msg);
        other.m_data = nullptr;
        other.m_len = 0;
        return *this;
    }
    
private:
    T* m_data;
    size_t m_len;
    int m_error;
    char m_error_msg[256];
};

using ByteResult = Result<uint8_t>;

class Streamer {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t MAX_DATA_SIZE = 256 * 1024 * 1024;
    
    explicit Streamer(std::span<const uint8_t, KEY_SIZE> key);
    ~Streamer();
    
    Streamer(const Streamer&) = delete;
    Streamer& operator=(const Streamer&) = delete;
    
    Streamer(Streamer&&) noexcept;
    Streamer& operator=(Streamer&&) noexcept;
    
    [[nodiscard]] ByteResult compress_encrypt(
        std::span<const uint8_t> src,
        std::span<const uint8_t, NONCE_SIZE> nonce
    );
    
    [[nodiscard]] ByteResult decrypt_decompress(
        std::span<const uint8_t> src
    );
    
    void encrypt_begin(std::span<const uint8_t, NONCE_SIZE> nonce);
    void encrypt_update(std::span<const uint8_t> chunk);
    [[nodiscard]] ByteResult encrypt_final();
    
    void decrypt_begin();
    void decrypt_update(std::span<const uint8_t> chunk);
    [[nodiscard]] ByteResult decrypt_final();
    
private:
    std::array<uint8_t, KEY_SIZE> m_key;
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

class KeyDeriver {
public:
    [[nodiscard]] static int derive_pbkdf2(
        std::string_view passphrase,
        std::span<const uint8_t> salt,
        uint8_t* out_key
    );

    [[nodiscard]] static std::vector<uint8_t> generate_salt(size_t len = 16);
};

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t* data;
    size_t   len;
    int      error;
    char     error_msg[256];
} StreamerResult_C;

StreamerResult_C streamer_compress_encrypt(
    const uint8_t* src,
    size_t         src_len,
    const uint8_t* key,
    const uint8_t* nonce
);

StreamerResult_C streamer_decrypt_decompress(
    const uint8_t* src,
    size_t         src_len,
    const uint8_t* key
);

void streamer_free(StreamerResult_C* r);

int streamer_derive_key(
    const char*    passphrase,
    const uint8_t* salt,
    size_t         salt_len,
    uint8_t*       out_key
);

#ifdef __cplusplus
}
#endif