// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#include <CLI/CLI.hpp>
#include <cstdint>
#include <ouroboros/error_code.hpp>
#include <ouroboros/reader.hpp>
#include <ouroboros/shm_file.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

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
        std::cerr << "Reader configured successfully\n";
        std::cerr << "  Chunk count: " << reader.chunk_count() << "\n";
        std::cerr << "  Buffer ID: " << reader.buffer_id() << "\n";
        std::cerr << "  Current chunk index: " << reader.current_chunk_index()
                  << "\n";

        std::size_t committed_count = 0;
        constexpr std::size_t chunks_per_row = 32;
        std::cerr
            << "  Chunk overview (C=committed, u=uncommitted, *=current):\n";
        std::cerr << "    range";
        std::cerr << "        state-map";
        std::cerr << "                                                         "
                     "token-range";
        std::cerr << "           offset-range\n";

        for (std::size_t row_begin = 0; row_begin < reader.chunk_count();
             row_begin += chunks_per_row)
        {
            auto row_end =
                std::min(row_begin + chunks_per_row, reader.chunk_count());
            auto first_token = reader.chunk_token(row_begin);
            auto last_token = first_token;
            auto first_offset = reader.chunk_offset(row_begin);
            auto last_offset = first_offset;
            std::string state_map;
            state_map.reserve((row_end - row_begin) * 2);

            for (std::size_t i = row_begin; i < row_end; ++i)
            {
                auto is_committed = reader.is_chunk_committed(i);
                if (is_committed)
                {
                    committed_count++;
                }

                state_map.push_back(is_committed ? 'C' : 'u');
                if (i == reader.current_chunk_index())
                {
                    state_map.push_back('*');
                }
                else
                {
                    state_map.push_back(' ');
                }
                if (is_committed)
                {
                    last_token = reader.chunk_token(i);
                    last_offset = reader.chunk_offset(i);
                }
            }

            std::cerr << "    [" << std::setw(4) << row_begin << "-"
                      << std::setw(4) << (row_end - 1) << "]  " << state_map
                      << "  [" << first_token << " -> " << last_token << "]"
                      << "    [" << first_offset << " -> " << last_offset << "]"
                      << "\n";
        }

        auto uncommitted_count = reader.chunk_count() - committed_count;
        std::cerr << "  Chunks committed: " << committed_count
                  << ", uncommitted: " << uncommitted_count << "\n";
    }

    std::ofstream out_file(output_file);
    if (!out_file.is_open())
    {
        std::cerr << "Error: Failed to open output file: " << output_file
                  << "\n";
        return 1;
    }

    // Read all entries and write them to the output file
    std::size_t entries_read = 0;
    while (true)
    {
        auto entry_result = reader.read_next();
        if (!entry_result.has_value())
        {
            if (verbose)
            {
                std::cerr << "Error reading entry: "
                          << entry_result.error().message() << "\n";
            }
            break;
        }

        // Write entry as string to output file
        out_file << entry_result.value() << "\n";
        entries_read++;
    }

    std::cerr << "Dumped " << entries_read << " entries\n";
    return 0;
}
