// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	MAX_STRING_LEN  = 10 * 1024 * 1024
	MEMORY_BUF_SIZE = 64 * 1024
	BUF_SIZE        = 4096
)

// Sentinel errors mirroring the nom error kinds used by the original Rust crate.
// ErrIncomplete corresponds to nom::Err::Incomplete (used for bad signatures),
// ErrEof corresponds to nom's ErrorKind::Eof (truncated input),
// ErrFail corresponds to nom's ErrorKind::Fail (general parse failure).
var (
	ErrIncomplete = errors.New("Incomplete")
	ErrEof        = errors.New("Eof")
	ErrFail       = errors.New("Fail")
	ErrTooLarge   = errors.New("TooLarge")
)

// cursor is a replacement for nom's &[u8] slicing parsers. It tracks a read
// position over a byte slice and yields little/big-endian scalars and slices.
type cursor struct {
	data []byte
	pos  int
}

func newCursor(data []byte) *cursor {
	return &cursor{data: data, pos: 0}
}

func (c *cursor) remaining() int {
	return len(c.data) - c.pos
}

func (c *cursor) isEmpty() bool {
	return c.pos >= len(c.data)
}

// rest returns the unconsumed portion of the buffer.
func (c *cursor) rest() []byte {
	return c.data[c.pos:]
}

// reset restarts the cursor over a new buffer (mirrors reassigning input in Rust).
func (c *cursor) reset(data []byte) {
	c.data = data
	c.pos = 0
}

func (c *cursor) need(n int) error {
	if n < 0 || c.remaining() < n {
		return fmt.Errorf("needed %d bytes, got %d: %w", n, c.remaining(), ErrEof)
	}
	return nil
}

// take returns the next n bytes without copying and advances the position.
func (c *cursor) take(n int) ([]byte, error) {
	if err := c.need(n); err != nil {
		return nil, err
	}
	b := c.data[c.pos : c.pos+n]
	c.pos += n
	return b, nil
}

// skip advances the position by n bytes.
func (c *cursor) skip(n int) error {
	if err := c.need(n); err != nil {
		return err
	}
	c.pos += n
	return nil
}

// takeWhile consumes bytes while fn returns true and returns them.
func (c *cursor) takeWhile(fn func(byte) bool) []byte {
	start := c.pos
	for c.pos < len(c.data) && fn(c.data[c.pos]) {
		c.pos++
	}
	return c.data[start:c.pos]
}

func (c *cursor) u8() (uint8, error) {
	if err := c.need(1); err != nil {
		return 0, err
	}
	v := c.data[c.pos]
	c.pos++
	return v, nil
}

func (c *cursor) u16() (uint16, error) {
	if err := c.need(2); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint16(c.data[c.pos:])
	c.pos += 2
	return v, nil
}

func (c *cursor) u32() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(c.data[c.pos:])
	c.pos += 4
	return v, nil
}

func (c *cursor) i32() (int32, error) {
	v, err := c.u32()
	return int32(v), err
}

func (c *cursor) i8() (int8, error) {
	v, err := c.u8()
	return int8(v), err
}

func (c *cursor) i16() (int16, error) {
	v, err := c.u16()
	return int16(v), err
}

func (c *cursor) u64() (uint64, error) {
	if err := c.need(8); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint64(c.data[c.pos:])
	c.pos += 8
	return v, nil
}

func (c *cursor) i64() (int64, error) {
	v, err := c.u64()
	return int64(v), err
}

// u32be reads a big-endian u32 (nom's be_u32).
func (c *cursor) u32be() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(c.data[c.pos:])
	c.pos += 4
	return v, nil
}

// u64be reads a big-endian u64 (nom's be_u64).
func (c *cursor) u64be() (uint64, error) {
	if err := c.need(8); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(c.data[c.pos:])
	c.pos += 8
	return v, nil
}

// u128be reads a big-endian 128-bit value (nom's be_u128).
func (c *cursor) u128be() ([16]byte, error) {
	var out [16]byte
	b, err := c.take(16)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// peekU32 reads a little-endian u32 at the current position without consuming it.
func (c *cursor) peekU32() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(c.data[c.pos:]), nil
}

// u128Hex formats a big-endian 128-bit value as 32 uppercase hex digits
// (equivalent to Rust's format!("{value:032X}")).
func u128Hex(v [16]byte) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 32)
	for i, b := range v {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}

type ReadCursor struct {
	mu sync.Mutex
	*bufio.Reader

	fd     io.ReadSeekCloser
	offset int64
}

func (self *ReadCursor) Read(buf []byte) (int, error) {
	n, err := io.ReadFull(self.Reader, buf)
	if err == io.ErrUnexpectedEOF {
		if n > 0 {
			err = nil
		} else {
			return 0, io.EOF
		}
	}

	self.offset += int64(n)
	if err == io.EOF {
		UlogsBreak()
	}

	return n, err
}

func (self *ReadCursor) u32() (uint32, error) {
	buf := []byte{0, 0, 0, 0}
	n, err := self.Read(buf)
	if n < 4 {
		return 0, io.EOF
	}
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf), nil
}

func (self *ReadCursor) u16() (uint16, error) {
	buf := []byte{0, 0}
	n, err := self.Read(buf)
	if n < 2 {
		return 0, io.EOF
	}
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(buf), nil
}

func (self *ReadCursor) u64() (uint64, error) {
	buf := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	n, err := self.Read(buf)
	if n < 8 {
		return 0, io.EOF
	}
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf), nil
}

func (self *ReadCursor) u128be() ([16]byte, error) {
	var out [16]byte
	n, err := self.Read(out[:])
	if n < 8 {
		return out, io.EOF
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

func (self *ReadCursor) string(start, length uint64) (string, error) {
	self.mu.Lock()
	defer self.mu.Unlock()

	_, err := self.fd.Seek(int64(start), io.SeekStart)
	if err != nil {
		return "", err
	}

	self.offset = int64(start)
	self.Reader.Reset(self.fd)

	// Read a buffer at the time until we hit a null termination.
	buf := make([]byte, BUF_SIZE)
	offset := start
	end := start + length
	res := strings.Builder{}

	for {
		to_read := int(end - offset)
		if to_read > len(buf) {
			to_read = len(buf)
		}

		// We are done!
		if to_read == 0 {
			return res.String(), nil
		}

		n, err := self.Read(buf[:to_read])
		if err != nil && err != io.EOF {
			return res.String(), err
		}

		// Search for null termination.
		for i := 0; i < n; i++ {
			if buf[i] == 0 {
				res.Write(buf[:i])
				return res.String(), nil
			}
		}

		res.Write(buf[:n])

		// A short read means the end of the file.
		if n < to_read {
			return res.String(), nil
		}

		offset += uint64(n)
	}
}

func (self *ReadCursor) Tell() int64 {
	return self.offset
}

func (self *ReadCursor) Pos(pos int64) error {
	n, err := self.fd.Seek(pos, io.SeekStart)
	self.offset = n
	self.Reader.Reset(self.fd)
	return err
}

func (self *ReadCursor) bytes(start, length int64) ([]byte, error) {
	self.mu.Lock()
	defer self.mu.Unlock()

	if length > MAX_STRING_LEN {
		length = MAX_STRING_LEN
	}

	_, err := self.fd.Seek(start, io.SeekStart)
	if err != nil {
		if err == io.EOF {
			UlogsBreak()
		}
		return nil, err
	}

	self.offset = start
	self.Reader.Reset(self.fd)

	if length < 0 || length > MAX_STRING_LEN {
		return nil, ErrTooLarge
	}

	res := make([]byte, length)
	n, err := self.Read(res)
	if err == io.EOF {
		err = nil
	}
	return res[:n], err
}

func (self *ReadCursor) skip(n int) error {
	_, err := self.take(n)
	if err == io.EOF {
		UlogsBreak()
	}

	return err
}

func (self *ReadCursor) take(n int) ([]byte, error) {
	if n < 0 || n > MAX_STRING_LEN {
		return nil, ErrTooLarge
	}

	buf := make([]byte, n)
	n, err := self.Read(buf)
	return buf[:n], err
}

// Swallow all bytes of delim until the reader is positioned at the
// first non-delim char.
func (self *ReadCursor) read_bytes(delim byte) error {
	for {
		buf, err := self.Reader.Peek(BUF_SIZE)
		if err != nil && err != io.EOF {
			return err
		}
		if err == io.EOF {
			UlogsBreak()
		}

		for i := 0; i < len(buf); i++ {
			if buf[i] != delim {
				return self.skip(i)
			}
		}

		if len(buf) == 0 {
			return io.EOF
		}

		// The entire buf was delim, skip it all.
		self.skip(len(buf))
	}
}

func (self *ReadCursor) Close() {
	self.fd.Close()
}

func NewReadCursor(reader io.ReadSeekCloser) *ReadCursor {
	return &ReadCursor{
		Reader: bufio.NewReaderSize(reader, MEMORY_BUF_SIZE),
		fd:     reader,
	}
}

type nopReadSeekCloser struct {
	io.ReadSeeker
}

func (nopReadSeekCloser) Close() error {
	return nil
}

func NewReadCursorFromBuffer(buf []byte) *ReadCursor {
	return NewReadCursor(nopReadSeekCloser{bytes.NewReader(buf)})
}
