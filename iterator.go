// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// UnifiedLogIterator iterates through the chunks in a tracev3 file. Each call
// to Next returns the data (header, catalog(s), oversize) for one catalog
// chunk, mirroring the Rust crate's UnifiedLogIterator.
type UnifiedLogIterator struct {
	Reader   *ReadCursor
	Header   []HeaderChunk
	Evidence string

	Logger *Logger
}

// Next returns the parsed Unified Log data for the next catalog. It returns
// false when there is no more data to process.
//
// If a catalog chunk is encountered while a catalog is already loaded, the
// iterator stops and rewinds to that chunk so it will be processed on the next
// call.
func (u *UnifiedLogIterator) Next() (*UnifiedLogData, bool) {
	logger := u.Logger

	unifiedLogData := UnifiedLogData{
		Header:   u.Header,
		Evidence: u.Evidence,
	}

	// Keep a local copy of the catalog so we know when a new catalog
	// chunk starts
	var catalogData UnifiedLogCatalogData

loop:
	for {
		offset := u.Reader.Tell()

		preamble, err := parsePreamble(u.Reader)
		if err != nil {
			// We already read the catalog, return what we have
			if catalogData.Catalog.ChunkTag != 0 {
				break
			}

			// We could not find a catalog but we still hit EOF. This
			// could be the last chunk.
			return nil, false
		}
		chunkSize := preamble.ChunkDataSize

		if chunkSize > ^uint64(0)-chunkPreambleSize {
			logger.Debugf("Large chunkSize at header %v", chunkSize)
			return nil, false
		}
		switch preamble.ChunkTag {
		case headerChunk:
			getHeaderData(u.Reader, preamble, &unifiedLogData, logger)

		case catalogChunk:
			// We already have a catalog - return what we have and
			// rewind the cursor to the start of this catalog
			// chunk. The next call to Next() will collect the catalog
			// and the records after it.
			if catalogData.Catalog.ChunkTag != 0 {
				u.Reader.Pos(offset)
				break loop
			}
			getCatalogData(u.Reader, preamble, &catalogData, logger)

		case chunksetChunk:
			getChunksetLogData(
				u.Reader, preamble, &catalogData,
				&unifiedLogData, logger)

		default:
			// Skip the chunk and ignore it
			u.Reader.skip(int(preamble.ChunkDataSize))
			logger.Printf(" Unknown chunk type: %v", preamble.ChunkTag)
		}

		paddingSize := paddingSize8(preamble.ChunkDataSize)
		next_offset := paddingSize + uint64(offset) + preamble.ChunkDataSize + chunkPreambleSize
		current_offset := uint64(u.Reader.Tell())

		// Should not really happen - we can not really go backwards.
		if current_offset > next_offset {
			u.Reader.Pos(int64(next_offset))
			break
		} else if next_offset > current_offset {
			err = u.Reader.skip(int(next_offset - current_offset))
			if err != nil {
				return nil, false
			}
		}
	}

	// Make sure to get the last catalog
	if catalogData.Catalog.ChunkTag != 0 {
		unifiedLogData.CatalogData = append(unifiedLogData.CatalogData,
			catalogData)
	}
	u.Header = unifiedLogData.Header
	return &unifiedLogData, true
}

// nomBytes takes size bytes from data, returning the remaining data and the
// taken bytes. Mirrors the Rust crate's nom_bytes helper.
func nomBytes(c *ReadCursor, size uint64) ([]byte, error) {
	return c.take(int(size))
}
