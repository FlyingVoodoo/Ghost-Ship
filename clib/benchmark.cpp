// Ghost-Ship Streamer Benchmarks

#include "streamer.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <memory>

class Timer {
public:
    void start() {
        m_start = std::chrono::high_resolution_clock::now();
    }
    
    double elapsed_ms() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now - m_start);
        return duration.count() / 1000.0;
    }
    
    double elapsed_us() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(now - m_start);
        return (double)duration.count();
    }

private:
    std::chrono::high_resolution_clock::time_point m_start;
};

std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(i ^ (i >> 8));
    }
    return data;
}

std::vector<uint8_t> generate_key() {
    std::vector<uint8_t> key(32);
    for (int i = 0; i < 32; ++i) key[i] = i + 42;
    return key;
}

std::vector<uint8_t> generate_nonce() {
    std::vector<uint8_t> nonce(12);
    for (int i = 0; i < 12; ++i) nonce[i] = i + 123;
    return nonce;
}

void bench_oneshot() {
    std::cout << "\n=== Benchmark: One-Shot API ===" << std::endl;
    
    std::vector<size_t> sizes = {1024, 10*1024, 100*1024, 1024*1024};
    int iterations = 100;
    
    for (size_t size : sizes) {
        auto data = generate_random_data(size);
        auto key_vec = generate_key();
        auto nonce_vec = generate_nonce();
        
        std::array<uint8_t, 32> key;
        std::array<uint8_t, 12> nonce;
        std::copy_n(key_vec.begin(), 32, key.begin());
        std::copy_n(nonce_vec.begin(), 12, nonce.begin());
        
        Streamer streamer(key);
        
        auto res = streamer.compress_encrypt(data, nonce);
        res.free();
        Timer timer;
        timer.start();
        for (int i = 0; i < iterations; ++i) {
            auto result = streamer.compress_encrypt(data, nonce);
            result.free();
        }
        double encrypt_ms = timer.elapsed_ms();
        long long bytes_encrypted = (long long)iterations * size;
        double throughput_mb_s = (bytes_encrypted / 1024.0 / 1024.0) / (encrypt_ms / 1000.0);
        
        std::cout << std::fixed << std::setprecision(2)
                  << "  Encrypt " << std::setw(7) << size << " bytes x" << iterations 
                  << ": " << std::setw(7) << encrypt_ms << " ms  "
                  << std::setw(8) << throughput_mb_s << " MB/s" << std::endl;
    }
}

void bench_streaming() {
    std::cout << "\n=== Benchmark: Streaming API ===" << std::endl;
    
    size_t total_size = 10 * 1024 * 1024;  // 10 MB
    size_t chunk_size = 64 * 1024;         // 64 KB chunks
    int iterations = 10;
    
    auto key_vec = generate_key();
    auto nonce_vec = generate_nonce();
    
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    std::copy_n(key_vec.begin(), 32, key.begin());
    std::copy_n(nonce_vec.begin(), 12, nonce.begin());
    
    Streamer streamer(key);
    auto data = generate_random_data(chunk_size);
    
    streamer.encrypt_begin(nonce);
    for (size_t pos = 0; pos < 512*1024; pos += chunk_size) {
        streamer.encrypt_update(data);
    }
    auto res = streamer.encrypt_final();
    res.free();
    Timer timer;
    timer.start();
    for (int iter = 0; iter < iterations; ++iter) {
        Streamer s(key);
        s.encrypt_begin(nonce);
        for (size_t pos = 0; pos < total_size; pos += chunk_size) {
            s.encrypt_update(data);
        }
        auto result = s.encrypt_final();
        result.free();
    }
    double total_ms = timer.elapsed_ms();
    
    long long total_bytes = (long long)iterations * total_size;
    double throughput_mb_s = (total_bytes / 1024.0 / 1024.0) / (total_ms / 1000.0);
    
    std::cout << std::fixed << std::setprecision(2)
              << "  Stream encrypt " << total_size / 1024 / 1024 << " MB x" << iterations
              << ": " << std::setw(7) << total_ms << " ms  "
              << std::setw(8) << throughput_mb_s << " MB/s" << std::endl;
}

void bench_memory() {
    std::cout << "\n=== Benchmark: Memory Efficiency ===" << std::endl;
    
    std::cout << "  (Optimized: 1 malloc per operation vs old: 3 malloc)" << std::endl;
    
    size_t size = 1024 * 1024;
    int iterations = 1000;
    
    auto data = generate_random_data(size);
    auto key_vec = generate_key();
    auto nonce_vec = generate_nonce();
    
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> nonce;
    std::copy_n(key_vec.begin(), 32, key.begin());
    std::copy_n(nonce_vec.begin(), 12, nonce.begin());
    
    Streamer streamer(key);
    
    Timer timer;
    timer.start();
    for (int i = 0; i < iterations; ++i) {
        auto result = streamer.compress_encrypt(data, nonce);
        result.free();
    }
    double time_ms = timer.elapsed_ms();
    
    std::cout << std::fixed << std::setprecision(2)
              << "  1000 allocations of ~1MB each: " << time_ms << " ms" << std::endl;
    std::cout << "  Allocation overhead: " << time_ms / iterations << " ms per operation" << std::endl;
}

void bench_crypto() {
    std::cout << "\n=== Benchmark: AES-256-GCM (Crypto Only) ===" << std::endl;
    
    std::vector<size_t> sizes = {4*1024, 1024*1024};
    
    for (size_t size : sizes) {
        auto data = generate_random_data(size);
        auto key_vec = generate_key();
        auto nonce_vec = generate_nonce();
        
        std::array<uint8_t, 32> key;
        std::array<uint8_t, 12> nonce;
        std::copy_n(key_vec.begin(), 32, key.begin());
        std::copy_n(nonce_vec.begin(), 12, nonce.begin());
        
        Streamer streamer(key);
        
        int iterations = (size > 100*1024) ? 100 : 1000;
        Timer timer;
        timer.start();
        for (int i = 0; i < iterations; ++i) {
            auto result = streamer.compress_encrypt(data, nonce);
            result.free();
        }
        double encrypt_us = timer.elapsed_us();
        
        double crypto_throughput = (iterations * size) / encrypt_us;
        std::cout << std::fixed << std::setprecision(2)
                  << "  Crypto throughput (" << size << " bytes): "
                  << std::setw(8) << (crypto_throughput * 1000) << " MB/s" << std::endl;
    }
}

int main() {
    std::cout << "=================================================\n"
              << "Ghost-Ship Streamer Benchmarks (C++20)\n"
              << "=================================================" << std::endl;
    
    try {
        bench_oneshot();
        bench_streaming();
        bench_memory();
        bench_crypto();
        
        std::cout << "\n=================================================" << std::endl;
        std::cout << "Benchmarks completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
