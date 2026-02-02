// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include <ouroboros/detail/buffer_format.hpp>
#include <ouroboros/reader.hpp>
#include <ouroboros/writer.hpp>

#include <benchmark/benchmark.h>

#include <cstring>
#include <string>
#include <vector>

namespace
{

constexpr std::size_t chunk_target_size = 1024 * 1024; // 1 MiB per chunk
constexpr std::size_t chunk_count = 16;

auto create_buffer() -> std::vector<uint8_t>
{
    const auto size = ouroboros::detail::buffer_format::compute_buffer_size(
        chunk_target_size, chunk_count);
    return std::vector<uint8_t>(size);
}

} // namespace

static void BM_Write(benchmark::State& state)
{
    const std::size_t entry_size = static_cast<std::size_t>(state.range(0));
    auto buffer = create_buffer();
    std::span<uint8_t> buffer_span(buffer);

    ouroboros::writer writer;
    writer.configure(buffer_span, chunk_target_size, chunk_count);

    std::string data(entry_size, 'x');

    for (auto _ : state)
    {
        writer.write(data);
    }
    const auto total_bytes =
        static_cast<double>(state.iterations()) * entry_size;
    state.counters["bytes_per_second"] =
        benchmark::Counter(total_bytes, benchmark::Counter::kIsRate);
}

static void BM_Read(benchmark::State& state)
{
    const std::size_t entry_size = static_cast<std::size_t>(state.range(0));
    auto buffer = create_buffer();
    // Calculate number of entries that fit into the buffer
    const std::size_t usable_space =
        buffer.size() -
        ouroboros::detail::buffer_format::compute_buffer_header_size(
            chunk_count);
    const std::size_t num_entries =
        usable_space /
        (entry_size + ouroboros::detail::buffer_format::entry_header_size);

    std::span<uint8_t> buffer_span(buffer);

    // Pre-fill buffer with entries
    {
        ouroboros::writer writer;
        writer.configure(buffer_span, chunk_target_size, chunk_count);
        std::string data(entry_size, 'x');
        for (std::size_t i = 0; i < num_entries; ++i)
        {
            writer.write(data);
        }
    }

    std::span<const uint8_t> const_buffer_span(buffer);

    std::size_t bytes_read_per_iteration = 0;
    for (auto _ : state)
    {
        ouroboros::reader reader;
        auto result = reader.configure(const_buffer_span);
        if (!result)
        {
            state.SkipWithError("Failed to configure reader");
            return;
        }

        std::size_t bytes_read = 0;
        while (auto entry_result = reader.read_next_entry())
        {
            bytes_read += entry_result->data.size();
            benchmark::DoNotOptimize(entry_result->data.size());
        }
        bytes_read_per_iteration = bytes_read;
    }
    const auto total_bytes =
        static_cast<double>(state.iterations()) * bytes_read_per_iteration;
    state.counters["bytes_per_second"] =
        benchmark::Counter(total_bytes, benchmark::Counter::kIsRate);
}

BENCHMARK(BM_Write)
    ->Arg(8)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096)
    ->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_Read)
    ->Args({8})
    ->Args({64})
    ->Args({256})
    ->Args({1024})
    ->Args({4096})
    ->Args({16384})
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
