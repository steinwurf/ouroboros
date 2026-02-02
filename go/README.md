# ouroboros-go

Pure-Go implementation of the Ouroboros shared-memory log reader.

## Requirements

- Go 1.21+
- Built `ouroboros_shm_generator` (run `waf build` from project root)

## Install

```bash
cd go
go mod download
go build ./...
```

## Test

Tests require the `ouroboros_shm_generator` binary. Run via waf from the project root:

```bash
waf build
waf go_test
```

Or manually:

```bash
export OUROBOROS_SHM_GENERATOR=/path/to/build/bin/ouroboros_shm_generator
cd go
go test ./...
```

## Usage

```go
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
    if entry.IsValid() {
        // Entry still valid (not overwritten)
    }
}
```
