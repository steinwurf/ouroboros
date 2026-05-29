// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

#ifdef ERROR_TAG
ERROR_TAG(none, "No error.")
ERROR_TAG(invalid_magic, "Invalid magic bytes.")
ERROR_TAG(unsupported_version, "Unsupported version.")
ERROR_TAG(invalid_chunk_count, "Invalid chunk count.")
ERROR_TAG(buffer_too_small, "Buffer too small for chunks.")
ERROR_TAG(no_data_no_committed_chunk,
          "No data available: no committed chunk found.")
ERROR_TAG(no_data_wrap_wait_for_chunk,
          "No data available: waiting for a newer chunk after wrap.")
ERROR_TAG(no_data_next_chunk_not_newer,
          "No data available: next chunk is not newer yet.")
ERROR_TAG(no_data_latest_chunk_not_newer,
          "No data available: latest chunk is not newer than current.")
ERROR_TAG(no_data_entry_uncommitted,
          "No data available: entry is not committed yet.")
ERROR_TAG(no_data_entry_not_written,
          "No data available: entry header is committed but length is zero.")
ERROR_TAG(entry_not_valid, "Entry not valid.")
ERROR_TAG(writer_finished, "Writer has finished; no more data will be written.")
ERROR_TAG(buffer_restarted, "Buffer was restarted; reader must reconfigure.")
ERROR_TAG(shared_memory_exists, "Shared memory segment already exists.")
ERROR_TAG(shared_memory_size_mismatch, "Shared memory segment size mismatch.")
ERROR_TAG(shared_memory_create_failed,
          "Failed to create shared memory segment.")
ERROR_TAG(shared_memory_open_failed, "Failed to open shared memory segment.")
ERROR_TAG(shared_memory_not_found, "Shared memory segment not found.")
ERROR_TAG(shared_memory_truncate_failed,
          "Failed to truncate shared memory segment.")
ERROR_TAG(shared_memory_map_failed, "Failed to map shared memory segment.")
ERROR_TAG(shared_memory_backing_allocation_failed,
          "Shared memory backing allocation failed.")
ERROR_TAG(shared_memory_stat_failed,
          "Failed to get shared memory segment status.")
ERROR_TAG(shared_memory_not_supported,
          "Shared memory not supported on this platform.")
ERROR_TAG(resume_not_initialized,
          "Cannot resume: buffer is not initialized (missing magic bytes).")
ERROR_TAG(resume_version_mismatch,
          "Cannot resume: buffer version does not match.")
ERROR_TAG(resume_chunk_count_mismatch,
          "Cannot resume: chunk count does not match.")
ERROR_TAG(resume_buffer_size_mismatch,
          "Cannot resume: buffer size does not match expected size.")
ERROR_TAG(resume_buffer_id_mismatch, "Cannot resume: buffer ID does not match.")
ERROR_TAG(resume_writer_finished, "Cannot resume: writer has finished.")
ERROR_TAG(resume_unexpected_wrap,
          "Cannot resume: unexpected wrap found in buffer.")
ERROR_TAG(resume_buffer_overflow, "Cannot resume: buffer overflow.")
ERROR_TAG(reserved_entry_length, "Reserved entry length value encountered.")
#else
#error "Missing ERROR_TAG"
#endif
