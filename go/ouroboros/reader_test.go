// Copyright (c) 2026 Steinwurf ApS
// SPDX-License-Identifier: MIT

package ouroboros

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	goshm "github.com/tmthrgd/go-shm"
)

const generatorInitialDelayUs = 500000

func findGeneratorExecutable(t *testing.T) string {
	t.Helper()
	path := os.Getenv("OUROBOROS_SHM_GENERATOR")
	if path == "" {
		t.Skip("OUROBOROS_SHM_GENERATOR is not set")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("invalid generator path: %v", err)
	}
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		t.Fatalf("OUROBOROS_SHM_GENERATOR points to invalid executable: %s", path)
	}
	return abs
}

func waitForShm(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		reader, err := NewReader(name)
		if err == nil {
			reader.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("shared memory segment %s did not appear within %v", name, timeout)
}

func startGenerator(t *testing.T, shmName string, bufferSize, recordCount, minPayload, maxPayload, seed int) (*exec.Cmd, string) {
	t.Helper()
	exe := findGeneratorExecutable(t)

	tmpFile, err := os.CreateTemp("", "ouroboros_test_*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	jsonPath := tmpFile.Name()
	tmpFile.Close()

	cmd := exec.Command(exe,
		"--name", shmName,
		"--size", fmt.Sprintf("%d", bufferSize),
		"--count", fmt.Sprintf("%d", recordCount),
		"--min-size", fmt.Sprintf("%d", minPayload),
		"--max-size", fmt.Sprintf("%d", maxPayload),
		"--seed", fmt.Sprintf("%d", seed),
		"--interval", "0",
		"--initial-delay", fmt.Sprintf("%d", generatorInitialDelayUs),
		"--json-out", jsonPath,
		"--no-unlink-at-exit",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		os.Remove(jsonPath)
		t.Fatalf("failed to start generator: %v", err)
	}

	if err := waitForShm(shmName, 5*time.Second); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(jsonPath)
		t.Fatal(err)
	}
	return cmd, jsonPath
}

func cleanupShm(shmName string) {
	shmName = strings.TrimPrefix(shmName, "/")
	_ = goshm.Unlink(shmName)
}

type expectedRecord struct {
	Index       int    `json:"index"`
	PayloadSize int    `json:"payload_size"`
	PayloadHex  string `json:"payload_hex"`
}

type expectedData struct {
	Records []expectedRecord `json:"records"`
}

func assertPayloadsMatch(t *testing.T, payloads [][]byte, expected *expectedData) {
	t.Helper()
	if len(payloads) != len(expected.Records) {
		t.Fatalf("payload count mismatch: got %d, expected %d", len(payloads), len(expected.Records))
	}
	for i, payload := range payloads {
		expHex := expected.Records[i].PayloadHex
		expBytes, err := hex.DecodeString(expHex)
		if err != nil {
			t.Fatalf("invalid expected hex at %d: %v", i, err)
		}
		if string(payload) != string(expBytes) {
			t.Errorf("payload %d mismatch: got %x, expected %x", i, payload, expBytes)
		}
	}
}

func runGeneratorAndReader(t *testing.T, shmName string, recordCount, bufferSize, minPayload, maxPayload, seed int) ([][]byte, *expectedData) {
	t.Helper()
	cmd, jsonPath := startGenerator(t, shmName, bufferSize, recordCount, minPayload, maxPayload, seed)
	defer func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		cleanupShm(shmName)
		os.Remove(jsonPath)
	}()

	reader, err := NewReader(shmName)
	if err != nil {
		t.Fatalf("failed to create reader: %v", err)
	}
	defer reader.Close()

	var payloads [][]byte
	deadline := time.Now().Add(30 * time.Second)
	for len(payloads) < recordCount && time.Now().Before(deadline) {
		entry, err := reader.ReadNextEntry()
		if err != nil {
			break
		}
		if entry != nil {
			payloads = append(payloads, entry.Data)
		} else {
			if cmd.ProcessState != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("generator failed: %v", err)
	}

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read json: %v", err)
	}
	var expected expectedData
	if err := json.Unmarshal(jsonData, &expected); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	return payloads, &expected
}

func uniqueShmName(t *testing.T) string {
	t.Helper()
	// Keep under typical shm name limits (~31 chars on some systems)
	return "/ouro_test_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:18]
}

func TestReaderBasic(t *testing.T) {
	payloads, expected := runGeneratorAndReader(t, uniqueShmName(t), 10, 10240, 10, 100, 42)
	assertPayloadsMatch(t, payloads, expected)
}

func TestReaderIterator(t *testing.T) {
	payloads, expected := runGeneratorAndReader(t, uniqueShmName(t), 5, 10240, 20, 50, 123)
	assertPayloadsMatch(t, payloads, expected)
}

func TestReaderLargePayloads(t *testing.T) {
	payloads, expected := runGeneratorAndReader(t, uniqueShmName(t), 20, 50000, 500, 1000, 456)
	assertPayloadsMatch(t, payloads, expected)
	for i, p := range payloads {
		if len(p) != expected.Records[i].PayloadSize {
			t.Errorf("payload %d size: got %d, expected %d", i, len(p), expected.Records[i].PayloadSize)
		}
	}
}

func TestReaderSingleRecord(t *testing.T) {
	payloads, expected := runGeneratorAndReader(t, uniqueShmName(t), 1, 2048, 100, 100, 789)
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
	expBytes, _ := hex.DecodeString(expected.Records[0].PayloadHex)
	if string(payloads[0]) != string(expBytes) {
		t.Errorf("payload mismatch")
	}
}

func TestReaderNonexistentShm(t *testing.T) {
	_, err := NewReader("/nonexistent_shm_segment_12345")
	if err == nil {
		t.Fatal("expected error for nonexistent shm")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestEntryAndChunkInfo(t *testing.T) {
	shmName := uniqueShmName(t)
	cmd, jsonPath := startGenerator(t, shmName, 10240, 5, 10, 50, 42)
	defer func() {
		if cmd.Process != nil && cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		cleanupShm(shmName)
		os.Remove(jsonPath)
	}()
	reader, err := NewReader(shmName)
	if err != nil {
		t.Fatalf("failed to create reader: %v", err)
	}
	defer reader.Close()

	var entries []*Entry
	deadline := time.Now().Add(30 * time.Second)
	for len(entries) < 5 && time.Now().Before(deadline) {
		entry, err := reader.ReadNextEntry()
		if err != nil {
			break
		}
		if entry != nil {
			entries = append(entries, entry)
		} else {
			if cmd.ProcessState != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("generator failed: %v", err)
	}

	jsonData, _ := os.ReadFile(jsonPath)
	var expected expectedData
	json.Unmarshal(jsonData, &expected)

	assertPayloadsMatch(t, func() [][]byte {
		var p [][]byte
		for _, e := range entries {
			p = append(p, e.Data)
		}
		return p
	}(), &expected)

	for _, entry := range entries {
		if len(entry.Data) == 0 {
			t.Error("entry data empty")
		}
		if entry.ChunkInfo.Index < 0 {
			t.Error("chunk info index < 0")
		}
		if !entry.ChunkInfo.IsCommitted {
			t.Error("chunk should be committed")
		}
		if entry.SequenceNumber == 0 {
			t.Error("sequence number should be > 0")
		}
		if !entry.IsValid() {
			t.Error("entry should be valid when reader still open")
		}
	}
}
