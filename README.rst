Ouroboros 🐍
============

Ouroboros is a library for a rotating ring buffer shared memory log with a single writer and multiple readers.

Features ✨
-----------

- 🔄 **Lock-free circular buffer** - No mutexes, no waiting, just pure speed
- 📝 **Variable-sized entries** - Log whatever you want, whenever you want
- 👥 **Multiple readers** - One writer, many readers
- 🔒 **Thread-safe** - Uses atomic operations
- 🌍 **Cross-platform** - Works on POSIX and Windows
- 🚀 **High performance** - Designed for real-time logging

How it works 🔧
---------------

The library implements a circular buffer divided into chunks:

1. The **writer** places entries into chunks sequentially
2. Multiple **readers** can read entries from different positions concurrently
3. When the buffer fills up, it wraps around and overwrites old entries
4. Readers use chunk tokens to detect if entries were overwritten during reading

Quick Start 🚀
--------------

.. code-block:: cpp

    #include <ouroboros/writer.hpp>
    #include <ouroboros/reader.hpp>

    // Create a writer
    ouroboros::writer writer;
    writer.configure(buffer, chunk_target_size, chunk_count);

    // Write some logs
    writer.write("Hello, world!");
    writer.write("This is a log entry");

    // Create a reader
    ouroboros::reader reader;
    reader.configure(buffer);

    // Read logs
    auto entry = reader.read_next();
    if (entry.has_value()) {
        std::cout << entry.value() << std::endl;
    }

Or use shared memory for inter-process logging:

.. code-block:: cpp

    #include <ouroboros/shm_log_writer.hpp>
    #include <ouroboros/shm_log_reader.hpp>

    // Writer process
    ouroboros::shm_log_writer writer;
    writer.configure("/my_log", 1024, 4);
    writer.write("Process A says hello!");

    // Reader process (different process)
    ouroboros::shm_log_reader reader;
    reader.configure("/my_log");
    auto entry = reader.read_next();

Building 🏗️
-----------

.. code-block:: bash

    # Using CMake
    cmake -B build
    cmake --build build

    # Or using Waf
    python3 waf configure
    python3 waf build

Installing the Python reader 🐍
--------------------------------

To install the pure-Python shared-memory log reader from this repository:

.. code-block:: bash

    python3 -m pip install "git+ssh://git@github.com/steinwurf/ouroboros.git#subdirectory=python"

See the `python/README.md <python/README.md>`_ for usage and API details.

Installing the Go reader 🐹
--------------------------

To use the pure-Go shared-memory log reader in another Go project, add it as a dependency.
The module lives in the ``go/`` subdirectory of this repository:

.. code-block:: bash

    go get github.com/steinwurf/ouroboros/go/ouroboros

Then import and use it:

.. code-block:: go

    import "github.com/steinwurf/ouroboros/go/ouroboros"

    reader, err := ouroboros.NewReader("/my_shm_name")
    if err != nil {
        log.Fatal(err)
    }
    defer reader.Close()

    for {
        entry := reader.ReadNextEntry()
        if entry == nil {
            break
        }
        fmt.Printf("Entry: %s\n", string(entry.Data))
    }

To use from a local checkout (e.g. for development), add a replace directive to your ``go.mod``:

.. code-block:: go

    replace github.com/steinwurf/ouroboros/go => /path/to/ouroboros/go

See the `go/README.md <go/README.md>`_ for requirements and more details.

Requirements 📦
---------------

- C++17 or later
- CMake 3.12+ or Waf build system
- Standard library (minimal dependencies)

License 📜
----------

Copyright (c) 2026 Steinwurf ApS. See LICENSE.rst for details.
