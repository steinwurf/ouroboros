"""Pytest configuration and fixtures for ouroboros_py tests."""

import json
import logging
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid
import pytest

from ouroboros_py import Reader

log = logging.getLogger(__name__)


def pytest_addoption(parser):
    """Add --ouroboros-shm-generator so waf/CI can pass the generator path without env."""
    parser.addoption(
        "--ouroboros-shm-generator",
        action="store",
        default=None,
        metavar="PATH",
        help="Path to ouroboros_shm_generator (overrides OUROBOROS_SHM_GENERATOR)",
    )


def pytest_configure(config):
    """If --ouroboros-shm-generator was given, set env for find_generator_executable()."""
    path = config.getoption("ouroboros_shm_generator", default=None)
    if path is not None:
        os.environ["OUROBOROS_SHM_GENERATOR"] = str(path)


# ---- Generator / reader helpers (used by fixtures and tests) ----

_GENERATOR_INITIAL_DELAY_US = 500_000  # 0.5s for reader to attach before first write


def find_generator_executable() -> pathlib.Path:
    """Resolve OUROBOROS_SHM_GENERATOR to an executable path. Raises if missing/invalid."""
    env_path = os.environ.get("OUROBOROS_SHM_GENERATOR")
    if not env_path:
        raise FileNotFoundError("OUROBOROS_SHM_GENERATOR is not set")
    path = pathlib.Path(env_path)
    if not (path.is_file() and os.access(path, os.X_OK)):
        raise FileNotFoundError(
            f"OUROBOROS_SHM_GENERATOR points to invalid executable: {env_path}"
        )
    return path.resolve()


def wait_for_shm(shm_name: str, timeout_sec: float = 5.0, poll_interval: float = 0.05) -> None:
    """Poll until the shared memory segment exists or raise TimeoutError."""
    from multiprocessing import shared_memory

    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            shm = shared_memory.SharedMemory(name=shm_name, create=False)
            shm.close()
            return
        except FileNotFoundError:
            time.sleep(poll_interval)
    raise TimeoutError(
        "Shared memory segment '{}' did not appear within {}s".format(shm_name, timeout_sec)
    )


def start_generator_async(
    shm_name: str,
    buffer_size: int,
    record_count: int,
    min_payload_size: int,
    max_payload_size: int,
    seed: int,
    interval_us: int = 0,
    initial_delay_us: int = _GENERATOR_INITIAL_DELAY_US,
) -> tuple[subprocess.Popen, pathlib.Path]:
    """Start the generator process and wait until shm exists. Returns (process, json_path)."""
    exe = find_generator_executable()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json_path = pathlib.Path(f.name)
    cmd = [
        str(exe),
        "--name", shm_name,
        "--size", str(buffer_size),
        "--count", str(record_count),
        "--min-size", str(min_payload_size),
        "--max-size", str(max_payload_size),
        "--seed", str(seed),
        "--interval", str(interval_us),
        "--initial-delay", str(initial_delay_us),
        "--json-out", str(json_path),
        "--no-unlink-at-exit",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for_shm(shm_name, timeout_sec=5.0)
    return proc, json_path


def read_realtime(
    reader: Reader,
    record_count: int,
    proc: subprocess.Popen,
    timeout_sec: float = 30.0,
    poll_interval_sec: float = 0.001,
) -> list:
    """Read payloads in real time until record_count or generator exits. Returns list of bytes."""
    payloads = []
    deadline = time.monotonic() + timeout_sec
    while len(payloads) < record_count and time.monotonic() < deadline:
        entry = reader.read_next()
        if entry is not None:
            payloads.append(entry)
        else:
            if proc.poll() is not None:
                break
            time.sleep(poll_interval_sec)
    return payloads


def cleanup_shm(shm_name: str) -> None:
    """Unlink shared memory segment if it exists. Ignores errors."""
    try:
        from multiprocessing import shared_memory

        try:
            shm = shared_memory.SharedMemory(name=shm_name, create=False)
            shm.close()
            if hasattr(shm, "unlink"):
                try:
                    shm.unlink()
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass
    except Exception:
        pass


def run_generator_and_reader(
    shm_name: str,
    record_count: int,
    *,
    buffer_size: int = 10240,
    min_payload_size: int = 10,
    max_payload_size: int = 100,
    seed: int = 42,
    interval_us: int = 0,
    initial_delay_us: int = _GENERATOR_INITIAL_DELAY_US,
) -> tuple[list, dict]:
    """
    Run generator async, attach reader, read_realtime until record_count, wait for generator,
    load JSON, then cleanup. Returns (payloads, expected_data) where expected_data is the
    parsed JSON with a "records" list.
    """
    proc, json_path = start_generator_async(
        shm_name=shm_name,
        buffer_size=buffer_size,
        record_count=record_count,
        min_payload_size=min_payload_size,
        max_payload_size=max_payload_size,
        seed=seed,
        interval_us=interval_us,
        initial_delay_us=initial_delay_us,
    )
    try:
        reader = Reader(shm_name)
        try:
            payloads = read_realtime(reader, record_count, proc)
            proc.wait(timeout=30)
            if proc.returncode != 0:
                _, stderr = proc.communicate()
                pytest.fail("Generator failed: {}".format(stderr))
            with open(json_path) as f:
                expected_data = json.load(f)
            return payloads, expected_data
        finally:
            reader.close()
    finally:
        if proc.returncode is None:
            proc.kill()
            proc.wait()
        cleanup_shm(shm_name)
        json_path.unlink(missing_ok=True)


def assert_payloads_match_json(payloads: list, expected_data: dict) -> None:
    """Assert payloads equal expected_data['records'] payload_hex (decoded)."""
    records = expected_data.get("records", [])
    assert len(payloads) == len(records), "payload count vs expected"
    for i, (payload, rec) in enumerate(zip(payloads, records)):
        expected = bytes.fromhex(rec["payload_hex"])
        assert payload == expected, "payload {} mismatch".format(i)


# ---- Fixtures (inject helpers so tests need not import conftest) ----


@pytest.fixture
def gen_reader():
    """Fixture that returns run_generator_and_reader."""
    return run_generator_and_reader


@pytest.fixture
def assert_payloads():
    """Fixture that returns assert_payloads_match_json."""
    return assert_payloads_match_json


# ---- Fixtures ----


@pytest.fixture
def unique_shm_name():
    """Unique shared memory name per test; cleanup on teardown."""
    name = "/ouroboros_test_{}".format(uuid.uuid4().hex[:16])
    yield name
    cleanup_shm(name)


# ---- Debug log buffer (print on failure) ----

_DEBUG_LOG_NAMES = (
    "ouroboros_py.reader",
    "ouroboros_py",
    "test_reader",
    "tests.test_reader",
)

# Buffer of recent log records (format strings) for display on failure
_debug_log_buffer = []
_DEBUG_BUFFER_MAX = 500


class _DebugBufferHandler(logging.Handler):
    """Buffer log records so we can print them when a test fails."""

    def emit(self, record):
        try:
            msg = self.format(record)
            _debug_log_buffer.append(msg)
            # keep buffer bounded
            while len(_debug_log_buffer) > _DEBUG_BUFFER_MAX:
                _debug_log_buffer.pop(0)
        except Exception:
            self.handleError(record)


def _install_debug_buffer():
    """Attach debug buffer handler to the test/reader loggers at DEBUG."""
    handler = _DebugBufferHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    for name in _DEBUG_LOG_NAMES:
        log = logging.getLogger(name)
        log.setLevel(logging.DEBUG)
        log.addHandler(handler)


def _print_debug_buffer():
    """Print buffered debug log lines to stderr (visible when a test fails)."""
    if not _debug_log_buffer:
        return
    print("\n--- DEBUG LOG (recent) ---", file=sys.stderr)
    for line in _debug_log_buffer[-300:]:  # last 300 lines
        print(line, file=sys.stderr)
    print("--- END DEBUG LOG ---\n", file=sys.stderr)


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """When a test fails, print buffered debug log messages."""
    outcome = yield
    report = outcome.get_result()
    if call.when == "call" and report.failed:
        _print_debug_buffer()


@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    """Configure loggers: INFO to console, DEBUG to buffer for failure output."""
    _install_debug_buffer()
    # Buffer sees DEBUG from these loggers
    for name in ("test_reader", "tests.test_reader"):
        logging.getLogger(name).setLevel(logging.DEBUG)


@pytest.fixture(autouse=True)
def clear_debug_buffer():
    """Clear the debug log buffer before each test so failures show only that test's logs."""
    _debug_log_buffer.clear()
    yield
