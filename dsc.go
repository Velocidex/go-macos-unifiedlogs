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
	"math"
)

// SharedCacheStrings contains the parsed shared string cache (dsc) data.
type SharedCacheStrings struct {
	Signature    uint32            `json:"signature"`
	MajorVersion uint16            `json:"major_version"` // Version 1 up to Big Sur. Monterey and later has Version 2!
	MinorVersion uint16            `json:"minor_version"`
	NumberRanges uint32            `json:"number_ranges"`
	NumberUUIDs  uint32            `json:"number_uuids"`
	Ranges       []RangeDescriptor `json:"ranges"`
	UUIDs        []UUIDDescriptor  `json:"uuids"`
	DSCUUID      string            `json:"dsc_uuid"`
}

// RangeDescriptor is a dsc range descriptor entry.
type RangeDescriptor struct {
	// In version 2 this is 8 bytes, in version 1 its 4 bytes
	RangeOffset uint64 `json:"range_offset"`
	DataOffset  uint32 `json:"data_offset"`
	RangeSize   uint32 `json:"range_size"`

	// Added in version 2. In version 1 the index is 4 bytes and is at
	// the start of the range descriptor
	UUIDIndex uint64 `json:"uuid_index"`
	Strings   []byte `json:"strings"`
}

// UUIDDescriptor is a dsc UUID descriptor entry.
type UUIDDescriptor struct {
	TextOffset uint64 `json:"text_offset"` // Size appears to be 8 bytes in Major version 2. 4 bytes in Major Version 1
	TextSize   uint32 `json:"text_size"`
	UUID       string `json:"uuid"`
	PathOffset uint32 `json:"path_offset"`
	PathString string `json:"path_string"` // Not part of format
}

func ParseDSC(
	c *ReadCursor, logger *Logger) (*SharedCacheStrings, error) {
	signature, err := c.u32()
	if err != nil {
		return nil, err
	}

	const expectedDSCSignature uint32 = 0x64736368
	if expectedDSCSignature != signature {
		logger.Printf(" Incorrect DSC file signature. Expected %d. Got: %d",
			expectedDSCSignature, signature)
		return nil, fmt.Errorf("incorrect DSC file signature: %w", ErrIncomplete)
	}

	sharedCacheStrings := &SharedCacheStrings{
		Signature: signature,
	}

	dscMajor, err := c.u16()
	if err != nil {
		return nil, err
	}
	dscMinor, err := c.u16()
	if err != nil {
		return nil, err
	}
	dscNumberRanges, err := c.u32()
	if err != nil {
		return nil, err
	}
	dscNumberUUIDs, err := c.u32()
	if err != nil {
		return nil, err
	}

	sharedCacheStrings.MinorVersion = dscMinor
	sharedCacheStrings.MajorVersion = dscMajor
	sharedCacheStrings.NumberRanges = dscNumberRanges
	sharedCacheStrings.NumberUUIDs = dscNumberUUIDs

	var rangeCount uint32
	for rangeCount < sharedCacheStrings.NumberRanges {
		rangeData, err := getRanges(c, dscMajor)
		if err != nil {
			return nil, err
		}
		sharedCacheStrings.Ranges = append(sharedCacheStrings.Ranges, rangeData)
		rangeCount++
	}

	var uuidCount uint32
	for uuidCount < sharedCacheStrings.NumberUUIDs {
		if uuidCount == 1521 {
			UlogsBreak()
		}
		uuidData, err := getUUIDs(c, dscMajor)
		if err != nil {
			if err == io.EOF {
				UlogsBreak()
			}
			return nil, err
		}
		sharedCacheStrings.UUIDs = append(sharedCacheStrings.UUIDs, uuidData)
		uuidCount++
	}

	for i := range sharedCacheStrings.UUIDs {
		pathString, err := c.string(
			uint64(sharedCacheStrings.UUIDs[i].PathOffset),
			math.MaxInt64)

		if err != nil {
			return nil, err
		}
		sharedCacheStrings.UUIDs[i].PathString = pathString
	}

	for i := range sharedCacheStrings.Ranges {
		strings, err := c.bytes(
			int64(sharedCacheStrings.Ranges[i].DataOffset),
			int64(sharedCacheStrings.Ranges[i].RangeSize))
		if err != nil {
			return nil, err
		}

		sharedCacheStrings.Ranges[i].Strings = strings
	}

	return sharedCacheStrings, nil
}

// getRanges gets range data, used by log entries to determine where the base
// string entry is located. Version 2 (Monterey and higher) changed the Range
// format a bit: range offset is now 8 bytes (vs 4 bytes) and starts at
// beginning; the uuid index was moved to end.
func getRanges(c *ReadCursor, version uint16) (RangeDescriptor, error) {
	const versionNumber uint16 = 2
	var rangeData RangeDescriptor

	var err error
	if version == versionNumber {
		rangeData.RangeOffset, err = c.u64()
		if err != nil {
			return RangeDescriptor{}, err
		}
	} else {
		// Get data based on version 1
		dscUUIDDescriptorIndex, err := c.u32()
		if err != nil {
			return RangeDescriptor{}, err
		}
		rangeData.UUIDIndex = uint64(dscUUIDDescriptorIndex)

		dscRangeOffset, err := c.u32()
		if err != nil {
			return RangeDescriptor{}, err
		}
		rangeData.RangeOffset = uint64(dscRangeOffset)
	}
	dscDataOffset, err := c.u32()
	if err != nil {
		return RangeDescriptor{}, err
	}
	dscRangeSize, err := c.u32()
	if err != nil {
		return RangeDescriptor{}, err
	}

	rangeData.DataOffset = dscDataOffset
	rangeData.RangeSize = dscRangeSize

	// UUID index is now located at the end of the format (instead of beginning)
	if version == versionNumber {
		dscUnknown, err := c.u64()
		if err != nil {
			return RangeDescriptor{}, err
		}
		rangeData.UUIDIndex = dscUnknown
	}
	return rangeData, nil
}

// getUUIDs gets UUID entries related to ranges.
func getUUIDs(c *ReadCursor, version uint16) (UUIDDescriptor, error) {
	var uuidData UUIDDescriptor

	const versionNumber uint16 = 2
	var err error
	if version == versionNumber {
		uuidData.TextOffset, err = c.u64()
		if err != nil {
			return UUIDDescriptor{}, err
		}
	} else {
		dscTextOffset, err := c.u32()
		if err != nil {
			return UUIDDescriptor{}, err
		}
		uuidData.TextOffset = uint64(dscTextOffset)
	}

	dscTextSize, err := c.u32()
	if err != nil {
		return UUIDDescriptor{}, err
	}
	dscUUID, err := c.u128be()
	if err != nil {
		return UUIDDescriptor{}, err
	}
	dscPathOffset, err := c.u32()
	if err != nil {
		return UUIDDescriptor{}, err
	}

	uuidData.TextSize = dscTextSize
	uuidData.UUID = u128Hex(dscUUID)
	uuidData.PathOffset = dscPathOffset

	return uuidData, nil
}
