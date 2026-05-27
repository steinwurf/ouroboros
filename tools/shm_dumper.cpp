// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <CLI/CLI.hpp>
#include <algorithm>
#include <cstdint>
#include <ouroboros/detail/buffer_format.hpp>
#include <ouroboros/error_code.hpp>
#include <ouroboros/reader.hpp>
#include <ouroboros/shm_file.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

auto is_end_of_dump(const std::error_code& error) -> bool
{
    if (!error)
    {
        return false;
    }

    const auto code = static_cast<ouroboros::error>(error.value());
    switch (code)
    {
    case ouroboros::error::no_data_no_committed_chunk:
    case ouroboros::error::no_data_wrap_wait_for_chunk:
    case ouroboros::error::no_data_next_chunk_not_newer:
    case ouroboros::error::no_data_latest_chunk_not_newer:
    case ouroboros::error::no_data_entry_uncommitted:
    case ouroboros::error::no_data_entry_not_written:
    case ouroboros::error::writer_finished:
        return true;
    default:
        return false;
    }
}

struct dump_stats
{
    std::size_t entries_dumped = 0;
    uint64_t max_sequence_number = 0;
    uint64_t max_chunk_token = 0;
    std::size_t read_errors = 0;
    uint64_t total_payload_bytes = 0;
    uint64_t total_on_wire_bytes = 0;
    bool writer_finished = false;
    bool have_entry_sizes = false;
    std::size_t min_entry_size = 0;
    std::size_t max_entry_size = 0;
    uint64_t entry_size_sum = 0;

    void record_entry(std::size_t on_wire_size, uint64_t sequence_number,
                      uint64_t chunk_token)
    {
        entries_dumped++;
        max_sequence_number = std::max(max_sequence_number, sequence_number);
        max_chunk_token = std::max(max_chunk_token, chunk_token);
        total_on_wire_bytes += on_wire_size;
        total_payload_bytes +=
            on_wire_size - ouroboros::detail::buffer_format::entry_header_size;
        entry_size_sum += on_wire_size;

        if (!have_entry_sizes)
        {
            have_entry_sizes = true;
            min_entry_size = on_wire_size;
            max_entry_size = on_wire_size;
        }
        else
        {
            min_entry_size = std::min(min_entry_size, on_wire_size);
            max_entry_size = std::max(max_entry_size, on_wire_size);
        }
    }
};

void print_title(std::ostream& out, std::string_view title)
{
    out << title << "\n";
}

template <class T>
void print_key_value(std::ostream& out, std::string_view key, const T& value,
                     std::size_t key_width = 28)
{
    out << "  " << std::left << std::setw(static_cast<int>(key_width)) << key
        << value << "\n";
}

void print_key_value_double(std::ostream& out, std::string_view key,
                            double value, std::size_t key_width = 28,
                            int precision = 1)
{
    auto old_flags = out.flags();
    auto old_precision = out.precision();
    out << "  " << std::left << std::setw(static_cast<int>(key_width)) << key
        << std::fixed << std::setprecision(precision) << value << "\n";
    out.flags(old_flags);
    out.precision(old_precision);
}

auto make_range_string(uint64_t begin, uint64_t end) -> std::string
{
    std::ostringstream stream;
    stream << "[" << begin << " -> " << end << "]";
    return stream.str();
}

void print_dump_stats(const dump_stats& stats)
{
    print_title(std::cerr, "Statistics");
    print_key_value(std::cerr, "Entries dumped:", stats.entries_dumped);
    print_key_value(std::cerr,
                    "Max sequence number:", stats.max_sequence_number);
    print_key_value(std::cerr, "Max chunk token seen:", stats.max_chunk_token);

    if (stats.have_entry_sizes)
    {
        const auto average_size = static_cast<double>(stats.entry_size_sum) /
                                  static_cast<double>(stats.entries_dumped);
        print_key_value(std::cerr,
                        "Entry size (on-wire) min:", stats.min_entry_size);
        print_key_value_double(std::cerr,
                               "Entry size (on-wire) avg:", average_size);
        print_key_value(std::cerr,
                        "Entry size (on-wire) max:", stats.max_entry_size);
    }

    print_key_value(std::cerr,
                    "Total payload bytes:", stats.total_payload_bytes);
    print_key_value(std::cerr,
                    "Total on-wire bytes:", stats.total_on_wire_bytes);
    print_key_value(std::cerr, "Writer finished marker:",
                    stats.writer_finished ? "yes" : "no");
    if (stats.read_errors > 0)
    {
        print_key_value(std::cerr, "Read errors:", stats.read_errors);
    }
}

} // namespace

auto main(int argc, char* argv[]) -> int
{
    CLI::App app{"Dump log entries from shared memory or a persistent binary "
                 "file starting from the lowest entry. Either --name or --bin "
                 "must be provided, but not both."};

    std::string shm_name;
    std::string bin_path;
    std::string output_file;
    bool verbose = false;

    app.add_option("--name", shm_name, "Shared memory name");
    app.add_option("--bin", bin_path, "Path to a persistent binary file");
    app.add_option("--output", output_file, "Output file path")->required();
    app.add_flag("--verbose", verbose, "Enable verbose output")
        ->default_val("false");

    try
    {
        app.parse(argc, argv);

        // Manual Exclusivity
        bool has_shm = !shm_name.empty();
        bool has_bin = !bin_path.empty();

        if (has_shm == has_bin) // Both true or both false
        {
            throw CLI::ValidationError(
                "Exactly one of --name or --bin must be provided.");
        }
    }
    catch (const CLI::ParseError& e)
    {
        std::cerr << app.help() << "\n";
        return app.exit(e);
    }

    if (verbose)
    {
        std::cerr << "Parsed arguments:\n";
        if (!shm_name.empty())
        {
            std::cerr << "  Shared Memory Name: " << shm_name << "\n";
        }
        else
        {
            std::cerr << "  Binary File Path: " << bin_path << "\n";
        }
        std::cerr << "  Output File: " << output_file << "\n";
    }
    std::vector<uint8_t> file_buffer;
    ouroboros::shm_file<ouroboros::shm_access::read_only> shm_file;

    const uint8_t* data_ptr = nullptr;
    std::size_t data_size = -1;

    if (!bin_path.empty())
    {
        std::ifstream file(bin_path, std::ios::binary | std::ios::ate);
        if (!file)
        {
            std::cerr << "Error: Could not open binary file: " << bin_path
                      << "\n";
            return 1;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        file_buffer.resize(static_cast<std::size_t>(size));

        if (!file.read(reinterpret_cast<char*>(file_buffer.data()), size))
        {
            std::cerr << "Error: Failed to read binary file content\n";
            return 1;
        }
        data_ptr = file_buffer.data();
        data_size = file_buffer.size();
    }
    else
    {
        auto shm_result = shm_file.open(shm_name);
        if (!shm_result.has_value())
        {
            std::cerr << "Error: Failed to open shared memory: "
                      << shm_result.error().message() << "\n";
            return 1;
        }
        data_ptr = shm_file.data();
        data_size = shm_file.size();
    }
    VERIFY(data_ptr != nullptr && data_size > 0,
           "Data pointer and size must be set");

    if (verbose)
    {
        std::cerr << "  Data size: " << data_size << " bytes\n";
    }

    // Configure the reader with from_lowest strategy to read all entries from
    // the beginning

    ouroboros::reader reader;
    auto config_result = reader.configure(
        {data_ptr, data_size}, ouroboros::reader::read_strategy::from_lowest);

    if (!config_result.has_value())
    {
        std::cerr << "Error: Failed to configure reader: "
                  << config_result.error().message() << "\n";
        return 1;
    }

    if (verbose)
    {
        print_title(std::cerr, "Reader Overview");
        print_key_value(std::cerr, "Chunk count:", reader.chunk_count(), 22);
        print_key_value(std::cerr, "Buffer ID:", reader.buffer_id(), 22);
        print_key_value(std::cerr,
                        "Current chunk index:", reader.current_chunk_index(),
                        22);
        print_key_value(std::cerr, "Current chunk token:",
                        reader.chunk_token(reader.current_chunk_index()), 22);
        print_key_value(std::cerr, "Current chunk offset:",
                        reader.chunk_offset(reader.current_chunk_index()), 22);

        std::size_t committed_count = 0;
        std::size_t committed_with_entries_count = 0;
        constexpr std::size_t chunks_per_row = 64;
        print_title(std::cerr, "  Chunk map");
        std::cerr << "    C=committed c=committed(no entries) U=uncommitted\n";
        std::cerr << "    " << std::left << std::setw(12) << "range "
                  << std::setw(65) << "state-map " << std::setw(27)
                  << "token-range offset-range\n";

        for (std::size_t row_begin = 0; row_begin < reader.chunk_count();
             row_begin += chunks_per_row)
        {
            auto row_end =
                std::min(row_begin + chunks_per_row, reader.chunk_count());
            bool has_committed_in_row = false;
            std::size_t first_committed_index = 0;
            std::size_t last_committed_index = 0;
            std::string state_map;
            state_map.reserve(row_end - row_begin);

            for (std::size_t i = row_begin; i < row_end; ++i)
            {
                auto is_committed = reader.is_chunk_committed(i);
                if (is_committed)
                {
                    committed_count++;
                    if (!has_committed_in_row)
                    {
                        first_committed_index = i;
                        has_committed_in_row = true;
                    }
                    last_committed_index = i;
                }

                if (is_committed)
                {
                    auto has_committed_entry = reader.has_committed_entry(i);
                    if (has_committed_entry)
                    {
                        committed_with_entries_count++;
                        state_map.push_back('C');
                    }
                    else
                    {
                        state_map.push_back('c');
                    }
                }
                else
                {
                    state_map.push_back('U');
                }
            }

            std::string token_range = "[n/a -> n/a]";
            std::string offset_range = "[n/a -> n/a]";

            if (has_committed_in_row)
            {
                auto first_token = reader.chunk_token(first_committed_index);
                auto last_token = reader.chunk_token(last_committed_index);
                auto first_offset = reader.chunk_offset(first_committed_index);
                auto last_offset = reader.chunk_offset(last_committed_index);
                token_range = make_range_string(first_token, last_token);
                offset_range = make_range_string(first_offset, last_offset);
            }

            std::cerr << "    [" << std::right << std::setw(4) << row_begin
                      << "-" << std::setw(4) << (row_end - 1) << "]  ";
            for (std::size_t i = 0; i < state_map.size(); ++i)
            {
                std::cerr << state_map[i];
            }
            std::cerr << std::string(chunks_per_row - state_map.size(), ' ')
                      << "  " << std::left << std::setw(27) << token_range
                      << " " << offset_range << "\n";
        }

        auto uncommitted_count = reader.chunk_count() - committed_count;
        std::cerr << "\n  Chunks committed: " << committed_count
                  << ", with entries: " << committed_with_entries_count
                  << ", uncommitted: " << uncommitted_count << "\n";
    }

    std::ofstream out_file(output_file);
    if (!out_file.is_open())
    {
        std::cerr << "Error: Failed to open output file: " << output_file
                  << "\n";
        return 1;
    }

    dump_stats stats;
    while (true)
    {
        auto entry_result = reader.read_next_entry();
        if (!entry_result.has_value())
        {
            if (entry_result.error() ==
                ouroboros::make_error_code(ouroboros::error::writer_finished))
            {
                stats.writer_finished = true;
            }
            else if (!is_end_of_dump(entry_result.error()))
            {
                stats.read_errors++;
                if (verbose)
                {
                    std::cerr << "Error reading entry: "
                              << entry_result.error().message() << "\n";
                }
            }
            break;
        }

        const auto& entry = entry_result.value();
        auto entry_str = std::string(entry.data);
        if (!entry.is_valid())
        {
            std::cerr << "Warning: Entry is changed while reading, skipping\n";
            break;
        }

        const std::size_t on_wire_size =
            entry_str.size() +
            ouroboros::detail::buffer_format::entry_header_size;

        stats.record_entry(on_wire_size, entry.sequence_number,
                           entry.chunk_token);

        out_file << entry_str << "\n";
    }

    if (verbose)
    {
        std::cerr << "\n";
        print_dump_stats(stats);
    }

    std::cerr << "Dumped " << stats.entries_dumped << " entries\n";
    return 0;
}
