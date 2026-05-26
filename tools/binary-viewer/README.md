# Ouroboros Binary File Viewer parser

JavaScript parser for the [Binary File Viewer](https://marketplace.visualstudio.com/items?itemName=maziac.binary-file-viewer) VS Code extension. It decodes:

- **`.shm`** — full ouroboros shared-memory captures (buffer header, chunk table, log entries)
- **`*_slice.bin` / entry slices** — a byte range that starts at a committed entry (e.g. `bad_slice.bin`)

## Setup

1. Install the **Binary File Viewer** extension (`maziac.binary-file-viewer`).
2. Add this folder to the extension’s parser path. In `.vscode/settings.json` (workspace or user):

```json
{
  "binary-file-viewer.parserFolders": [
    "tools/binary-viewer"
  ]
}
```

Use a **relative** path from the workspace root. Do **not** use `${workspaceFolder}` — the extension joins relative paths itself and does not expand VS Code variables, so `${workspaceFolder}/tools/binary-viewer` would resolve to a non-existent directory.

3. **Reload the window** after changing the setting (`Developer: Reload Window`), then open the binary again.

4. Open a `.shm` or slice `.bin` file → **Open With…** → **Binary File Viewer** (or set the viewer as default for that extension).
5. In the viewer toolbar, pick **ouroboros_shm.js** if multiple parsers are listed, then **Reload** after edits.

If you still see **“No parser available”**, check **Problems** for errors in `ouroboros_shm.js`, and confirm the folder exists at `<workspace>/tools/binary-viewer/ouroboros_shm.js`.

## Tips

- Keep `ouroboros_shm.js` open beside the binary file; **save** the parser to refresh the decode live.
- Click an **offset** column value to jump to the matching line in the parser.
- Entry listing stops after **500** entries for performance; edit `MAX_ENTRIES_SHOWN` in the parser if needed.
- Full-buffer layout matches `writer.hpp` / `buffer_format.hpp` (magic `OUROBLOG`, version 2, 4-byte entry headers with commit MSB).

## Slice files

A slice cut with `dd` from the middle of a buffer (no `OUROBLOG` header) is parsed as a **linear entry stream** from offset 0. Example:

```bash
dd if=test_files/bad.shm of=bad_slice.bin bs=1M skip=32830996 count=2670616 \
   iflag=skip_bytes,count_bytes status=progress
```
