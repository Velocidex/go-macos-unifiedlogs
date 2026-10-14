// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

// ChunksetChunk is the decompressed Chunkset data that contains the actual log
// entries.
type ChunksetChunk struct {
	ChunkTag         uint32 `json:"chunk_tag"`
	ChunkSubTag      uint32 `json:"chunk_sub_tag"`
	ChunkDataSize    uint64 `json:"chunk_data_size"`
	Signature        uint32 `json:"signature"` // should be "bv41"
	UncompressSize   uint32 `json:"uncompress_size"`
	BlockSize        uint32 `json:"block_size"`
	DecompressedData []byte `json:"decompressed_data"`
	Footer           uint32 `json:"footer"` // should be "bv4$"
}

// ParseChunkset parses the Chunkset data that contains the actual log entries.
func ParseChunkset(c *ReadCursor,
	preamble *LogPreamble,
	logger *Logger) (ChunksetChunk, error) {
	var chunksetChunk ChunksetChunk

	// chunk_input is the input starting at the compression signature.
	chunksetSig, err := c.u32()
	if err != nil {
		return chunksetChunk, err
	}
	chunksetUncompressSize, err := c.u32()
	if err != nil {
		return chunksetChunk, err
	}

	const bv41 = 825521762             // bv41 signature
	const bv41Uncompressed = 758412898 // bv41- signature

	// Data is already decompressed (Observed in tracev3 files in /var/db/diagnostics/Special)
	if chunksetSig == bv41Uncompressed {
		uncompressedData, err := c.take(int(chunksetUncompressSize))
		if err != nil {
			return chunksetChunk, err
		}
		chunksetChunk.DecompressedData = uncompressedData
		chunksetFooter, err := c.u32()
		if err != nil {
			return chunksetChunk, err
		}
		chunksetChunk.Footer = chunksetFooter
		return chunksetChunk, nil
	}

	// Only two likely to exist
	lzbitmapSigs := []uint32{206389850, 156058202, 223167066, 139280986}
	if containsU32(lzbitmapSigs, chunksetSig) {
		decomBytes, err := lzbitmapDecompressRemaining(c, logger)
		if err != nil {
			return chunksetChunk, err
		}
		// Always [6, 0, 0, 0, 0, 0]?
		// Maybe its a version number?
		chunksetFooter, err := c.u32()
		if err != nil {
			return chunksetChunk, err
		}

		chunksetChunk.DecompressedData = decomBytes
		chunksetChunk.Footer = chunksetFooter

		return chunksetChunk, nil
	}

	// Compressed data signature should be bv41
	if chunksetSig != bv41 {
		logger.Printf(" Incorrect compression signature expected bv41, got: %v", chunksetSig)
		return chunksetChunk, ErrIncomplete
	}

	chunksetBlockSize, err := c.u32()
	if err != nil {
		return chunksetChunk, err
	}

	chunksetChunk.ChunkTag = preamble.ChunkTag
	chunksetChunk.ChunkSubTag = preamble.ChunkSubTag
	chunksetChunk.ChunkDataSize = preamble.ChunkDataSize
	chunksetChunk.Signature = chunksetSig
	chunksetChunk.UncompressSize = chunksetUncompressSize
	chunksetChunk.BlockSize = chunksetBlockSize

	compressedData, err := c.take(int(chunksetBlockSize))
	if err != nil {
		return chunksetChunk, err
	}

	// The decompressed data contains multiple log entries
	decompressedData := make([]byte, chunksetUncompressSize)
	if _, err := lz4.UncompressBlock(compressedData, decompressedData); err != nil {
		logger.Printf(" Failed to decompress log data: %v", err)
		return chunksetChunk, ErrIncomplete
	}
	chunksetChunk.DecompressedData = decompressedData

	chunksetFooter, err := c.u32()
	if err != nil {
		return chunksetChunk, err
	}
	chunksetChunk.Footer = chunksetFooter

	return chunksetChunk, nil
}

// ParseChunksetData parses each log (chunk) in the decompressed Chunkset data.
func ParseChunksetData(c *ReadCursor,
	unifiedLogData *UnifiedLogCatalogData,
	logger *Logger) error {
	const chunkPreambleSize = 16 // Include preamble size in total chunk size

	// Loop through decompressed chunkset data until all log entries (chunks) are read
	for {
		preamble, err := parsePreamble(c)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		chunkSize := preamble.ChunkDataSize

		// Grab all data associated with log (chunk) data
		chunkSizeInt, ok := u64ToUint(chunkSize)
		if !ok {
			logger.Printf("chunk size too large: %v", ErrTooLarge)
			return fmt.Errorf("chunk size too large: %w", ErrTooLarge)
		}
		chunkData, err := c.take(chunkSizeInt)
		if err != nil {
			return err
		}
		getChunksetData(chunkData, preamble, unifiedLogData, logger)

		err = c.read_bytes(0)
		if err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}

// getChunksetData parses the log entry (chunk) chunk based on type.
func getChunksetData(data []byte,
	preamble *LogPreamble,
	unifiedLogData *UnifiedLogCatalogData, logger *Logger) {

	switch preamble.ChunkTag {
	case firehoseChunk:
		firehoseData, err := parseFirehosePreamble(data, preamble, logger)
		if err != nil {
			logger.Printf(" Failed to parse firehose log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Firehose = append(unifiedLogData.Firehose, *firehoseData)
	case oversizeChunk:
		oversize, err := parseOversize(data, preamble, logger)
		if err != nil {
			logger.Printf(" Failed to parse oversize log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Oversize = append(unifiedLogData.Oversize, oversize)
	case statedumpChunk:
		statedump, err := ParseStatedump(data, preamble, logger)
		if err != nil {
			logger.Printf(" Failed to parse statedump log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Statedump = append(unifiedLogData.Statedump, statedump)
	case simpledumpChunk:
		simpledump, err := parseSimpledump(data, preamble, logger)
		if err != nil {
			logger.Printf(" Failed to parse simpledump log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Simpledump = append(unifiedLogData.Simpledump, simpledump)
	default:
		logger.Printf(" Unknown chunkset type: %v", preamble.ChunkTag)
	}
}

// containsU32 reports whether v is present in values.
func containsU32(values []uint32, v uint32) bool {
	for _, value := range values {
		if value == v {
			return true
		}
	}
	return false
}
