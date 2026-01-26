// Copyright (c) 2023 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#include <CLI/CLI.hpp>
#include <ouroboros/reader.hpp>
#include <ouroboros/shm_log_reader.hpp>

#include <fstream>
#include <iostream>
#include <string>

auto main(int argc, char* argv[]) -> int
{
    CLI::App app{"Dump shared memory log entries starting from lowest token"};

    std::string shm_name;
    std::string output_file;

    app.add_option("--name", shm_name, "Shared memory name")->required();
    app.add_option("--output", output_file, "Output file path")->required();

    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        std::cerr << app.help() << "\n";
        return app.exit(e);
    }

    // Configure reader with from_lowest strategy
    ouroboros::shm_log_reader reader;
    auto config_result = reader.configure(
        shm_name, ouroboros::reader::read_strategy::from_lowest);
    if (!config_result.has_value())
    {
        std::cerr << "Error: Failed to configure reader: "
                  << config_result.error().message() << "\n";
        return 1;
    }

    // Open output file
    std::ofstream out_file(output_file);
    if (!out_file.is_open())
    {
        std::cerr << "Error: Failed to open output file: " << output_file << "\n";
        return 1;
    }

    // Read all entries and write them to the output file
    std::size_t entries_read = 0;
    while (true)
    {
        auto entry_result = reader.read_next();
        if (!entry_result.has_value())
        {
            // No more data available (normal end of reading)
            break;
        }

        // Write entry as string to output file
        out_file << entry_result.value() << "\n";
        entries_read++;
    }

    std::cerr << "Dumped " << entries_read << " entries\n";

    return 0;
}
