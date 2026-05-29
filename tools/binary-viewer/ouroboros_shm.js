// Parser for Binary File Viewer (maziac.binary-file-viewer)
// https://github.com/maziac/binary-file-viewer
//
// Decodes ouroboros shared-memory captures (.shm) and raw entry slices (.bin).

const MAGIC_BYTES = [0x47, 0x4f, 0x4c, 0x42, 0x4f, 0x52, 0x55, 0x4f]; // "GOLBORUO" / OUROBLOG LE
const VERSION = 2;
const BUFFER_HEADER_SIZE = 24;
const CHUNK_ROW_SIZE = 16;
const ENTRY_HEADER_SIZE = 4;
const ENTRY_ALIGNMENT = 4;
const MAX_ENTRIES_SHOWN = 5000;
const MAX_PAYLOAD_PREVIEW = 256;

function alignUp(size, align) {
	return (size + align - 1) & ~(align - 1);
}

function hasMagicAtStart(fileData) {
	const bytes = fileData.getBytesAt(0, 8);
	if (bytes.length < 8) {
		return false;
	}
	for (let i = 0; i < 8; i++) {
		if (bytes[i] !== MAGIC_BYTES[i]) {
			return false;
		}
	}
	return true;
}

function formatPayloadPreview() {
	const text = getStringValue();
	if (text.length <= MAX_PAYLOAD_PREVIEW) {
		return text;
	}
	return text.substring(0, MAX_PAYLOAD_PREVIEW) + '…';
}

function parseEntryBody() {
	read(4);

	const val = BigInt(getHex0xValue());

	const committed = (val & (1n << 31n)) == 0x80000000n;
	const length = Number(val & ((1n << 31n) - 1n));

	if (!committed) {
		addRow('Commit flag', 'clear', 'Entry header is not committed');
		return { stop: true, reason: 'uncommitted' };
	}

	if (length === 0) {
		addRow('Type', 'not written (0)', 'No entry at this offset yet');
		return { stop: true, reason: 'length-0' };
	}
	if (length === 1) {
		addRow('Type', 'wrap (1)', 'Writer wrapped; reader jumps to chunk 0');
		return { stop: true, reason: 'wrap' };
	}
	if (length === 2) {
		addRow('Type', 'reserved (2)', 'Reserved special length');
		return { stop: true, reason: 'reserved' };
	}
	if (length === 3) {
		addRow('Type', 'writer finished (3)', 'No more entries will be written');
		return { stop: true, reason: 'finished' };
	}

	if (length < ENTRY_HEADER_SIZE) {
		addRow('Type', 'invalid', 'Length smaller than entry header');
		return { stop: true, reason: 'invalid' };
	}

	const payloadSize = length - ENTRY_HEADER_SIZE;
	addRow('Payload size', '' + payloadSize, 'Bytes after 4-byte header');

	read(payloadSize);
	addRow('Payload preview', formatPayloadPreview(), 'UTF-8 text when applicable');

	const padding = alignUp(length, ENTRY_ALIGNMENT) - length;
	if (padding > 0) {
		read(padding);
		addRow('Alignment padding', padding + ' B', 'Pad to 4-byte boundary');
	}

	return { stop: false, onWireSize: length, committed: committed };
}

function parseEntryStream(sectionTitle) {
	addRow(sectionTitle, '', 'Sequential committed entries from current offset');
	let entryIndex = 0;
	let stopReason = '';

	while (entryIndex < MAX_ENTRIES_SHOWN) {
		let entryStop = false;

		readRowWithDetails('Entry #' + entryIndex, () => {
			const result = parseEntryBody();
			if (result.stop) {
				entryStop = true;
				stopReason = result.reason;
			}
			return {
				value: result.stop ? stopReason : '' + (result.onWireSize || 0) + ' B',
				description: 'Log entry at aligned offset ' + (result.committed ? "(committed)" : "(uncommitted)")
			};
		});

		if (entryStop) {
			break;
		}

		entryIndex++;
	}
	// If more data dump it
	if (getRemainingSize() > 0) {
		addRow('…', '', 'Stopped after ' + entryIndex + ' entries; ' + getRemainingSize() + ' B more');
		read(2048); // Read some more to show in hex viewer
		addMemDump(true);
	}
}

function parseBufferHeader() {
	read(8);
	addRow('Magic', getStringValue(), 'OUROBLOG (0x4F55524F424C4F47)');
	read(4);
	addRow('Version', getNumberValue(), 'Buffer format version (expected ' + VERSION + ')');
	read(4);
	const chunkCount = getNumberValue();
	addRow('Chunk count', '' + chunkCount, 'Number of chunk table rows');
	read(8);
	addRow('Buffer ID', BigInt(getHex0xValue()), 'Writer-configured 64-bit buffer id');

	const headerTableSize = BUFFER_HEADER_SIZE + chunkCount * CHUNK_ROW_SIZE;

	return { chunkCount, headerTableSize };
}

function parseChunkTable(chunkCount) {
	addRow('Chunk table', chunkCount + ' x 16 B', 'Offset (8) + token (8) per chunk');


	readRowWithDetails("Chunk Table",
		() => {
			for (let i = 0; i < chunkCount; i++) {
				read(8);
				const offset_and_commit_flag = BigInt(getHex0xValue());
				read(8);
				const token = BigInt(getHex0xValue());

				const committed = (offset_and_commit_flag & (1n << 63n)) !== 0n;
				const offset = BigInt(offset_and_commit_flag & ((1n << 63n) - 1n));
				addRow(
					'Chunk #' + i,
					committed ? 'Committed' : 'Uncommitted',
					'Offset ' + offset + ', token ' + token
				);
			}
		},
		false
	);
}

function parseFullBuffer() {
	const { chunkCount, headerTableSize } = parseBufferHeader();

	parseChunkTable(chunkCount);
	setOffset(headerTableSize);
	addRow(
		'Data region',
		'from offset ' + headerTableSize,
		'Inferred start of chunk 0 payload when layout is contiguous'
	);

	parseEntryStream('Entries (from current offset)');
}

registerFileType((fileExt, filePath, fileData) => {
	if (fileExt === 'shm') {
		return true;
	}
	if (fileExt === 'bin' || fileExt === 'slice') {
		if (filePath && filePath.toLowerCase().includes('slice')) {
			return true;
		}
	}
	if (fileData && hasMagicAtStart(fileData)) {
		return true;
	}
	return false;
});

registerParser(() => {
	var offset = getOffset();
	read(8);
	const magic = getStringValue();
	setOffset(offset);
	const isOuroblog = magic === 'GOLBORUO';

	if (isOuroblog) {
		parseFullBuffer();
	} else {
		parseEntryStream('Ouroboros entry slice (no buffer header)');
	}
});
