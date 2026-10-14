// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "encoding/binary"

// Heavily influenced by https://github.com/fox-it/dissect.util/blob/main/dissect/util/compression/lzbitmap.py -- Apache license

// lzbitmapDecompress decompresses lzbitmap data. Seen in Unified Logs starting in Golden Gate.
func lzbitmapDecompressRemaining(
	c *ReadCursor, logger *Logger) ([]byte, error) {
	u24 := func(c *ReadCursor) int {
		buf, err := c.take(3)
		if err != nil {
			return 0
		}
		buf = append(buf, 0)
		return int(binary.LittleEndian.Uint32(buf))
	}

	if c.Buffered() < 3 {
		return nil, ErrIncomplete
	}
	signature := u24(c)
	// ZBM
	const magicSignature = 5063258
	if signature != magicSignature {
		logger.Printf(" Unexpected signature for LZBITMAP %d. Wanted ZBM", signature)
		return nil, ErrFail
	}

	if c.Buffered() < 4 {
		return nil, ErrIncomplete
	}

	buf, err := c.take(1)
	if err != nil {
		return nil, ErrIncomplete
	}
	flags := buf[0]

	if !checkLzbitmapFlags(flags, logger) {
		return nil, ErrFail
	}

	const flagLarge = 1
	const flagNoRunLength = 4
	maxChunk := 0x4000
	if flags&flagLarge != 0 {
		maxChunk = 0x8000
	}

	runLengthEncodedTokens := flags&flagNoRunLength == 0
	bitmapsCount := 13
	if runLengthEncodedTokens {
		bitmapsCount = 12
	}
	var decomBuf []byte

	const chunkHeaderSize = 6
	input := 4
	for {
		compressSize := u24(c)
		decomSize := u24(c)

		if compressSize > decomSize+chunkHeaderSize {
			logger.Printf(" Bad LZBITMAP chunk size: %d vs %d", compressSize, decomSize+chunkHeaderSize)
			return nil, ErrFail
		}

		if decomSize == 0 {
			break
		}

		if decomSize > maxChunk {
			logger.Printf(" Chunk decompressed size is larger (%d) than expected max chunk size: %d", decomSize, maxChunk)
			return nil, ErrFail
		}

		// Data is not compressed. We can just append to our decompressed data
		if compressSize == decomSize+chunkHeaderSize {
			buf, err := c.take(decomSize)
			if err != nil {
				return nil, err
			}
			decomBuf = append(decomBuf, buf...)
			continue
		}

		// We have compressed data we need to decompress now
		// Distance - Contains distance data needed determine how far back to look in the decompressed data
		// Bitmap - Contains bitmap bits used to determine how to read and decompress the data. Bit 1 - read compressed data, bit 0 - copy decompressed data
		// Token - Determines if distance or bitmap should be used
		distanceOffset := u24(c)
		bitmapOffset := u24(c)
		tokenOffset := u24(c)
		currentOffset := 15

		// Compressed data includes the offsets we read above. We need
		// to include it in the total compressed data
		compressedData, err := c.take(compressSize)
		if err != nil {
			return nil, err
		}
		const bitmapSize = 17
		if bitmapSize > compressSize {
			logger.Printf(" Bitmap size larger than compressed data size: %d vs %d", bitmapSize, compressSize)
			return nil, ErrFail
		}
		bitsData := compressedData[:compressSize-bitmapSize]

		tokenMap := []lzBitmapToken{{0, 0}, {0, 1}, {0, 2}}

		for i := 0; i < bitmapsCount; i++ {
			bit := i * 10
			if bit/8+2 > len(bitsData) {
				return nil, ErrIncomplete
			}
			bytes := uint16(bitsData[bit/8]) | uint16(bitsData[bit/8+1])<<8
			value := bytes >> (bit % 8)
			tokenMap = append(tokenMap, lzBitmapToken{uint8(value & 0xff), uint8((value >> 8) & 3)})
		}

		if distanceOffset < 15 ||
			distanceOffset > bitmapOffset ||
			bitmapOffset > tokenOffset ||
			tokenOffset > compressSize-bitmapSize {
			logger.Printf(" Token offset %d larger than compressed data: %d bytes", tokenOffset, compressSize)
			return nil, ErrFail
		}

		tokenBytes := compressedData[tokenOffset : len(compressedData)-bitmapSize]
		tokens := &lzBitmapTokens{data: tokenBytes}
		distance := 8

		for decomSize > 0 {
			index, ok := tokens.next()
			if !ok {
				return nil, ErrFail
			}

			var repeatToken uint32
			if runLengthEncodedTokens {
				if index == 0xf {
					return nil, ErrFail
				}
				value, ok := getLzRepeatToken(tokens, decomSize)
				if !ok {
					return nil, ErrFail
				}
				repeatToken = value
			} else {
				repeatToken = 1
			}

			for r := uint32(0); r < repeatToken; r++ {
				if int(index) >= len(tokenMap) {
					return nil, ErrFail
				}
				bitmap := tokenMap[index].bitmap
				distanceBytes := tokenMap[index].distanceBytes

				// Indexes less than 3 use bitmap from bitmap bytes
				if index < 3 {
					if int(bitmapOffset) >= len(compressedData) {
						return nil, ErrFail
					}
					bitmap = compressedData[bitmapOffset]
					bitmapOffset++
				}

				switch distanceBytes {
				case 0:
				case 1:
					if int(distanceOffset) >= len(compressedData) {
						return nil, ErrFail
					}
					distance = int(compressedData[distanceOffset])
					distanceOffset++
				case 2:
					if int(distanceOffset)+2 > len(compressedData) {
						return nil, ErrFail
					}
					distance = int(uint16(compressedData[distanceOffset]) | uint16(compressedData[distanceOffset+1])<<8)
					distanceOffset += 2
				default:
					return nil, ErrFail
				}

				for i := 0; i < 8; i++ {
					if bitmap&1 != 0 {
						if currentOffset >= len(compressedData) {
							return nil, ErrFail
						}
						decomBuf = append(decomBuf, compressedData[currentOffset])
						currentOffset++
					} else {
						if distance == 0 {
							logger.Printf(" Got distance 0 for checked_sub on decompressed data")
							return nil, ErrFail
						}
						sourceOffset := len(decomBuf) - distance
						if sourceOffset < 0 {
							return nil, ErrFail
						}
						decomBuf = append(decomBuf, decomBuf[sourceOffset])
					}

					bitmap >>= 1
					decomSize--

					if decomSize == 0 {
						break
					}
				}

				if decomSize == 0 {
					break
				}
			}
		}

		input += compressSize
	}

	return decomBuf, nil
}

// lzbitmapDecompress decompresses lzbitmap data and discards the remaining input
// bytes. Seen in Unified Logs starting in Golden Gate.
func lzbitmapDecompress(
	c *ReadCursor, logger *Logger) ([]byte, error) {
	decompressed, err := lzbitmapDecompressRemaining(c, logger)
	return decompressed, err
}

// lzBitmapToken holds a bitmap and the number of distance bytes for a lzbitmap token.
type lzBitmapToken struct {
	bitmap        uint8
	distanceBytes uint8
}

// lzBitmapTokens emits low nibbles before high nibbles and supports a one-item
// peek, mirroring the Rust Peekable<FlatMap> used by get_tokens.
type lzBitmapTokens struct {
	data []byte
	pos  int
	cur  uint8
	have bool
}

func (t *lzBitmapTokens) next() (uint8, bool) {
	if t.have {
		t.have = false
		return t.cur, true
	}
	if t.pos >= len(t.data) {
		return 0, false
	}
	b := t.data[t.pos]
	t.pos++
	t.cur = b >> 4
	t.have = true
	return b & 0xf, true
}

func (t *lzBitmapTokens) peek() (uint8, bool) {
	if t.have {
		return t.cur, true
	}
	if t.pos >= len(t.data) {
		return 0, false
	}
	return t.data[t.pos] & 0xf, true
}

// getLzRepeatToken determines if the bitmap token should be used again
func getLzRepeatToken(tokens *lzBitmapTokens, remaining int) (uint32, bool) {
	if remaining <= 8 {
		return 1, true
	}
	value, ok := tokens.peek()
	if !ok {
		return 0, false
	}
	if value != 0xf {
		return 1, true
	}
	if _, ok := tokens.next(); !ok {
		return 0, false
	}
	total := uint32(4)
	value = 0xf
	for value == 0xf {
		nextValue, ok := tokens.next()
		if !ok {
			return 0, false
		}
		value = nextValue
		total += uint32(value)
	}
	return total, true
}

// checkLzbitmapFlags checks for unknown flags
func checkLzbitmapFlags(
	flag uint8, logger *Logger) bool {
	switch flag {
	case 0x9, 0xc:
		return true
	case 0x8, 0xd:
		// These flags could exist but so far have not been seen in wild
		logger.Printf(" Got possible flag %d", flag)
		return true
	default:
		logger.Printf(" Got unsupported flag %d", flag)
		return false
	}
}
