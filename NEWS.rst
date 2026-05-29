News for ouroboros
==================

This file lists the major changes between versions. For a more detailed list of
every change, see the Git log.

Latest
------
* Major: Split generic no-data reader errors into more specific error codes.
* Minor: Reworked `shm_dumper` to be more robust against chunks containing uncommitted data.
* Minor: Improved POSIX SHM size-mismatch handling.
* Minor: Changed writer entry overwrite behavior when at the end of a chunk.

3.0.0
-----
* Major: Bump Cli11 to v2.6.2
* Minor: Add ``--bin`` to dumper such that it can take raw binary snapshots of shared memory files, and make it such that dumper is always build by toplevel projects such that its available for usage in them.

2.0.0
-----
* Major: Reworked the shared-memory C++ API to separate mapping ownership from
  log protocol logic. Added `shm_file` for shared-memory lifecycle and
  access (`data() const`/`data()`), and removed `shm_log_reader` and
  `shm_log_writer`. Shared-memory users now configure `reader`/`writer`
  directly from mapped spans.

1.2.0
-----
* Minor: Added writer finish (end-of-stream) support. Writers can signal
  completion with a special entry (length 3), allowing readers to detect
  that no more data will be written and unlink shared memory.
* Minor: Added writer takeover support. A new writer can resume from where
  a previous writer left off (peaceful takeover) or force-reinitialize the
  buffer (force takeover).
* Minor: Added buffer ID support for identifying log instances and detecting
  buffer restarts.
* Minor: Added reserved entry length (length 2) handling across C++, Go,
  and Python readers.
* Minor: Added error codes for takeover failures, buffer restarts, and
  writer-finished conditions.

1.1.0
-----
* Minor: License changed from proprietary to MIT.

1.0.0
-----
* Major: Initial release.
