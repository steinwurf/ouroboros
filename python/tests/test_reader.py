"""Tests for ouroboros_py.Reader."""

import pytest

from ouroboros_py import Reader
from ouroboros_py.reader import ReaderError


def test_reader_basic(unique_shm_name, gen_reader, assert_payloads):
    """Generator runs async; reader reads in real time; payloads match JSON."""
    payloads, expected = gen_reader(
        unique_shm_name,
        record_count=10,
        buffer_size=10240,
        min_payload_size=10,
        max_payload_size=100,
        seed=42,
    )
    assert_payloads(payloads, expected)


def test_reader_iterator(unique_shm_name, gen_reader, assert_payloads):
    """Same flow as basic; validates data matches when reading in real time."""
    payloads, expected = gen_reader(
        unique_shm_name,
        record_count=5,
        buffer_size=10240,
        min_payload_size=20,
        max_payload_size=50,
        seed=123,
    )
    assert_payloads(payloads, expected)


def test_reader_context_manager(unique_shm_name, gen_reader, assert_payloads):
    """Same flow; Reader used internally by run_generator_and_reader."""
    payloads, expected = gen_reader(
        unique_shm_name,
        record_count=3,
        buffer_size=5120,
        min_payload_size=5,
        max_payload_size=10,
        seed=999,
    )
    assert_payloads(payloads, expected)


def test_reader_large_payloads(unique_shm_name, gen_reader, assert_payloads):
    """Larger buffer and payload sizes; also assert payload_size in JSON."""
    payloads, expected = gen_reader(
        unique_shm_name,
        record_count=20,
        buffer_size=50000,
        min_payload_size=500,
        max_payload_size=1000,
        seed=456,
    )
    assert_payloads(payloads, expected)
    for payload, rec in zip(payloads, expected["records"]):
        assert len(payload) == rec["payload_size"]


def test_reader_single_record(unique_shm_name, gen_reader):
    """Single record; assert exactly one payload and match hex."""
    payloads, expected = gen_reader(
        unique_shm_name,
        record_count=1,
        buffer_size=2048,
        min_payload_size=100,
        max_payload_size=100,
        seed=789,
    )
    assert len(payloads) == 1
    assert payloads[0] == bytes.fromhex(expected["records"][0]["payload_hex"])


def test_reader_nonexistent_shm():
    """Reader on non-existent shared memory raises ReaderError."""
    with pytest.raises(ReaderError, match="not found"):
        Reader("/nonexistent_shm_segment_12345")
