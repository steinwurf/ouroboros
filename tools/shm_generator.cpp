// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include <CLI/CLI.hpp>
#include <ouroboros/detail/buffer_format.hpp>
#include <ouroboros/shm_log_writer.hpp>
#include <ouroboros/shm_platform.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// Convert bytes to hex string
auto bytes_to_hex(const std::vector<uint8_t>& bytes) -> std::string
{
    std::ostringstream oss;
    for (uint8_t b : bytes)
    {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(b);
    }
    return oss.str();
}

// Calculate chunk configuration from buffer size
// Tries to use 4 chunks with reasonable target size
auto calculate_chunk_config(std::size_t buffer_size)
    -> std::pair<std::size_t, std::size_t>
{
    constexpr std::size_t default_chunk_count = 4;
    constexpr std::size_t buffer_header_size = 16;
    constexpr std::size_t chunk_row_size = 16;

    std::size_t chunk_table_size = default_chunk_count * chunk_row_size;
    std::size_t header_size = buffer_header_size + chunk_table_size;

    if (buffer_size < header_size + 1024)
    {
        // Buffer too small, use minimum chunk count
        std::size_t chunk_count = 1;
        chunk_table_size = chunk_count * chunk_row_size;
        header_size = buffer_header_size + chunk_table_size;
        std::size_t chunk_target_size =
            (buffer_size > header_size) ? (buffer_size - header_size) : 512;
        return {chunk_target_size, chunk_count};
    }

    std::size_t available_space = buffer_size - header_size;
    std::size_t chunk_target_size = available_space / default_chunk_count;

    return {chunk_target_size, default_chunk_count};
}

struct RecordInfo
{
    std::size_t index;
    std::size_t payload_size;
    std::vector<uint8_t> payload;
};

auto write_json_output(const std::string& path,
                       const std::vector<RecordInfo>& records) -> bool
{
    std::ofstream file(path);
    if (!file.is_open())
    {
        std::cerr << "Error: Failed to open JSON output file: " << path << "\n";
        return false;
    }

    file << "{\n";
    file << "  \"records\": [\n";

    for (std::size_t i = 0; i < records.size(); ++i)
    {
        const auto& record = records[i];
        file << "    {\n";
        file << "      \"index\": " << record.index << ",\n";
        file << "      \"payload_size\": " << record.payload_size << ",\n";
        file << "      \"payload_hex\": \"" << bytes_to_hex(record.payload)
             << "\"\n";
        file << "    }";
        if (i < records.size() - 1)
        {
            file << ",";
        }
        file << "\n";
    }

    file << "  ]\n";
    file << "}\n";

    return true;
}

// Global flag for signal handling
static std::atomic<bool> g_interrupted{false};
static std::string g_shm_name;
static std::atomic<bool> g_writer_configured{false};

// Signal handler for Ctrl+C
void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        g_interrupted.store(true);
        // Unlink shared memory immediately if it was configured
        if (g_writer_configured.load() && !g_shm_name.empty())
        {
            ouroboros::unlink_shm(g_shm_name);
        }
    }
}

auto main(int argc, char* argv[]) -> int
{
    CLI::App app{"Generate deterministic log records in shared memory"};

    std::string shm_name;
    std::size_t buffer_size = 0;
    uint64_t record_count = 0;
    uint64_t min_payload_size = 0;
    uint64_t max_payload_size = 0;
    uint64_t seed = 0;
    uint64_t interval_us = 0;
    uint64_t initial_delay_us = 0;
    std::string json_output_path;
    bool unlink_at_exit = true;

    app.add_option("--name", shm_name, "Shared memory name")->required();
    app.add_option("--size", buffer_size, "Shared memory size in bytes")
        ->required()
        ->check(CLI::NonNegativeNumber);
    app.add_option("--count", record_count, "Number of records to generate")
        ->required()
        ->check(CLI::PositiveNumber);
    app.add_option("--min-size", min_payload_size,
                   "Minimum payload size in bytes")
        ->required()
        ->check(CLI::PositiveNumber);
    app.add_option("--max-size", max_payload_size,
                   "Maximum payload size in bytes")
        ->required()
        ->check(CLI::PositiveNumber);
    app.add_option("--seed", seed, "Random seed for deterministic generation")
        ->default_val(std::random_device()());

    app.add_option("--interval", interval_us, "Microseconds between entries")
        ->required();
    app.add_option("--initial-delay", initial_delay_us,
                   "Microseconds to wait before writing first entry")
        ->default_val(0);
    app.add_option("--json-out", json_output_path,
                   "JSON output file path describing all records")
        ->required();
    bool no_unlink_at_exit = false;
    app.add_flag("--unlink-at-exit", unlink_at_exit,
                 "Unlink shared memory segment on exit (default: true)");
    app.add_flag("--no-unlink-at-exit", no_unlink_at_exit,
                 "Keep shared memory segment after exit (for readers)")
        ->excludes("--unlink-at-exit");

    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        std::cerr << app.help() << "\n";
        return app.exit(e);
    }

    if (no_unlink_at_exit)
    {
        unlink_at_exit = false;
    }

    if (min_payload_size > max_payload_size)
    {
        std::cerr << "Error: --min-size (" << min_payload_size
                  << ") must be <= --max-size (" << max_payload_size << ")\n";
        return 1;
    }

    // Set up signal handler for Ctrl+C
    std::signal(SIGINT, signal_handler);
    g_shm_name = shm_name;

    // Calculate chunk configuration
    auto [chunk_target_size, chunk_count] = calculate_chunk_config(buffer_size);

    // Create shared memory writer
    ouroboros::shm_log_writer writer;
    auto config_result = writer.configure(shm_name, chunk_target_size,
                                          chunk_count, unlink_at_exit);
    if (!config_result.has_value())
    {
        std::cerr << "Error: Failed to configure shared memory writer: "
                  << config_result.error().message() << "\n";
        return 1;
    }
    g_writer_configured.store(true);

    // Print reader information in easily parseable JSON format
    std::cout << "{\n";
    std::cout << "  \"shm_name\": \"" << shm_name << "\",\n";
    std::cout << "  \"buffer_size\": " << writer.buffer_size() << ",\n";
    std::cout << "  \"chunk_target_size\": " << writer.chunk_target_size()
              << ",\n";
    std::cout << "  \"chunk_count\": " << writer.chunk_count() << ",\n";
    std::cout << "  \"max_entry_size\": " << writer.max_entry_size() << "\n";
    std::cout << "}\n";

    // Wait for initial delay before starting to write
    if (initial_delay_us > 0)
    {
        std::this_thread::sleep_for(
            std::chrono::microseconds(initial_delay_us));
    }

    // Generate deterministic payloads
    std::mt19937 gen(seed);
    std::uniform_int_distribution<std::size_t> payload_size_dist(
        min_payload_size, max_payload_size);
    std::vector<RecordInfo> records;
    records.reserve(record_count);

    for (uint64_t i = 0; i < record_count; ++i)
    {
        // Check if interrupted by Ctrl+C
        if (g_interrupted.load())
        {
            std::cerr << "\nInterrupted by user (Ctrl+C).\n";
            break;
        }

        // Generate payload size using deterministic RNG
        std::size_t payload_size = payload_size_dist(gen);

        // Generate deterministic payload data
        std::vector<uint8_t> payload;
        payload.resize(payload_size);
        std::uniform_int_distribution<int> dist(0, 255);

        for (auto& b : payload)
        {
            b = static_cast<uint8_t>(dist(gen));
        }

        // Check if payload fits
        if (payload_size > writer.max_entry_size())
        {
            std::cerr << "Error: Generated payload size " << payload_size
                      << " exceeds maximum entry size "
                      << writer.max_entry_size() << "\n";
            return 1;
        }

        // Write entry
        std::string_view payload_view(
            reinterpret_cast<const char*>(payload.data()), payload.size());
        writer.write(payload_view);

        // Store record info
        records.push_back({i, payload_size, std::move(payload)});

        // Sleep between entries
        if (i < record_count - 1 && interval_us > 0)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(interval_us));
        }
    }

    // Write JSON output
    if (!write_json_output(json_output_path, records))
    {
        return 1;
    }

    return 0;
}
