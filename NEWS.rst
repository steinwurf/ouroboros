News for ouroboros
==================

This file lists the major changes between versions. For a more detailed list of
every change, see the Git log.

Latest
------
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
