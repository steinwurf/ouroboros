// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace test_helpers
{

/// Helper to create aligned buffer
/// std::vector typically provides 8-byte aligned memory on most platforms
inline auto create_aligned_buffer(std::size_t size) -> std::vector<uint8_t>
{
    std::vector<uint8_t> buffer(size);
    // Verify alignment - most allocators provide 8-byte aligned memory
    // If this fails, the writer's VERIFY will catch it during configure()
    return buffer;
}

/// Helper to generate a string entry consisting of the entry_counter followed
/// by a random number of characters to reach target size
inline auto generate_entry(std::size_t entry_counter,
                           std::size_t target_size) -> std::string
{
    std::string entry = std::to_string(entry_counter);
    while (entry.size() < target_size)
    {
        entry += 'A' + (entry_counter % 26); // Cycle through A-Z
    }

    return entry;
}

/// Helper to generate unique shared memory names for tests
inline auto generate_shm_name() -> std::string
{
    static std::atomic<uint32_t> counter{0};
    auto c = counter.fetch_add(1, std::memory_order_relaxed);
#ifdef _WIN32
    auto pid = static_cast<uint32_t>(::_getpid());
#else
    auto pid = static_cast<uint32_t>(::getpid());
#endif

    // "/ouroboros_" (10) + pid (up to 10) + "_" (1) + counter (up to 10) = <=
    // 31-ish
    return "/ouroboros_" + std::to_string(pid) + "_" + std::to_string(c);
}

}
