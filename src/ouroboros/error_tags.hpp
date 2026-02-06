// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#ifdef ERROR_TAG
ERROR_TAG(none, "No error.")
ERROR_TAG(invalid_magic, "Invalid magic bytes.")
ERROR_TAG(unsupported_version, "Unsupported version.")
ERROR_TAG(invalid_chunk_count, "Invalid chunk count.")
ERROR_TAG(buffer_too_small, "Buffer too small for chunks.")
ERROR_TAG(no_data_available, "No data available to read.")
ERROR_TAG(entry_not_valid, "Entry not valid.")
ERROR_TAG(writer_finished, "Writer has finished; no more data will be written.")
ERROR_TAG(buffer_restarted, "Buffer was restarted; reader must reconfigure.")
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
ERROR_TAG(takeover_not_initialized,
          "Cannot takeover: buffer is not initialized (missing magic bytes).")
ERROR_TAG(takeover_version_mismatch,
          "Cannot takeover: buffer version does not match.")
ERROR_TAG(takeover_chunk_count_mismatch,
          "Cannot takeover: chunk count does not match.")
ERROR_TAG(takeover_buffer_size_mismatch,
          "Cannot takeover: buffer size does not match expected size.")
ERROR_TAG(takeover_buffer_id_mismatch,
          "Cannot takeover: buffer ID does not match.")
ERROR_TAG(takeover_writer_finished, "Cannot takeover: writer has finished.")
ERROR_TAG(takeover_unexpected_wrap,
          "Cannot takeover: unexpected wrap found in buffer.")
ERROR_TAG(takeover_buffer_overflow, "Cannot takeover: buffer overflow.")
ERROR_TAG(reserved_entry_length, "Reserved entry length value encountered.")
#else
#error "Missing ERROR_TAG"
#endif
