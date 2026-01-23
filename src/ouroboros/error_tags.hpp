// Copyright (c) 2025 Steinwurf ApS
// All Rights Reserved
//
// THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE OF STEINWURF
// The copyright notice above does not evidence any
// actual or intended publication of such source code.

#ifdef ERROR_TAG
ERROR_TAG(none, "No error.")
ERROR_TAG(invalid_magic, "Invalid magic bytes.")
ERROR_TAG(unsupported_version, "Unsupported version.")
ERROR_TAG(invalid_chunk_count, "Invalid chunk count.")
ERROR_TAG(buffer_too_small, "Buffer too small for chunks.")
ERROR_TAG(no_data_available, "No data available to read.")
ERROR_TAG(entry_not_valid, "Entry not valid.")
ERROR_TAG(shared_memory_exists, "Shared memory segment already exists.")
ERROR_TAG(shared_memory_create_failed,
          "Failed to create shared memory segment.")
ERROR_TAG(shared_memory_open_failed, "Failed to open shared memory segment.")
ERROR_TAG(shared_memory_not_found, "Shared memory segment not found.")
ERROR_TAG(shared_memory_truncate_failed,
          "Failed to truncate shared memory segment.")
ERROR_TAG(shared_memory_map_failed, "Failed to map shared memory segment.")
ERROR_TAG(shared_memory_stat_failed,
          "Failed to get shared memory segment status.")
ERROR_TAG(shared_memory_not_supported,
          "Shared memory not supported on this platform.")
#else
#error "Missing ERROR_TAG"
#endif
