// Package hmsg implements reading and writing of length- and checksum-prefixed
// messages.
package hmsg

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
)

// MaxMessageSize returns the maximum message size needed to contain a payload
// of payloadSize, checksum for hashfn, and the length prefix of the message.
func MaxMessageSize(payloadSize int64, hashfn HashFunc) int64 {
	const maxMsg64 = math.MaxInt64 - binary.MaxVarintLen64
	payloadSize += int64(hashfn().Size())
	if payloadSize <= 0 || payloadSize > maxMsg64 {
		return math.MaxInt64
	}
	lengthSize := uvarintLen(uint64(payloadSize)) // Bytes needed for the maximum length prefix
	return payloadSize + int64(lengthSize)
}

// VerifyError is returned when a receive's message's checksum does not match
// its contents.
type VerifyError struct {
	Got  []byte
	Want []byte
}

// Error implements error.
func (c *VerifyError) Error() string {
	return fmt.Sprintf(
		"message checksums don't match: sent(%x) <> received(%x)",
		c.Got, c.Want)
}

// IsVerifyError returns whether err is a VerifyError.
func IsVerifyError(err error) bool {
	_, ok := err.(*VerifyError)
	return ok
}

// Messenger reads and writes messages with length and checksum prefixes.
type Messenger struct {
	maxSize  uint64
	hashSize int
	hashfn   HashFunc
}

// NewMessenger allocates a new Messenger for reading and writing length- and
// checksum-prefixed messages.
//
// maxMsgSize specifies the maximum size of a message in bytes, and must be
// greater than the minimum size needed to contain a message length prefix for
// maxMsgSize and its checksum. If maxMsgSize would be invalid, or the hash
// function does not return a valid message size (or is nil), NewMessenger
// returns an error.
func NewMessenger(maxMsgSize int64, hashfn HashFunc) (*Messenger, error) {
	if hashfn == nil {
		return nil, errors.New("hash function is nil")
	}

	hashSize := hashfn().Size() // Bytes needed for the checksum
	if hashSize < 0 {
		return nil, fmt.Errorf("hash size must be >= 0; got %d", hashSize)
	}

	lengthSize := int(uvarintLen(uint64(maxMsgSize))) // Bytes needed for the maximum length prefix
	maxHeaderSize := int64(lengthSize + hashSize)     // Maximum header size

	if maxMsgSize <= 0 {
		maxMsgSize = 0
	} else if maxMsgSize <= maxHeaderSize {
		return nil, fmt.Errorf("max message size must be > %d bytes (header size); got %d", maxHeaderSize, maxMsgSize)
	}
	return &Messenger{
		maxSize:  uint64(maxMsgSize),
		hashSize: hashSize,
		hashfn:   hashfn,
	}, nil
}

// MaxMessageSize returns the maximum message size.
// Message size includes the length prefix and checksum size.
//
// If the Messenger was not given an explicit message size, its maximum is
// math.MaxInt64.
func (m *Messenger) MaxMessageSize() int64 {
	if m.maxSize == 0 {
		return math.MaxInt64
	}
	return int64(m.maxSize)
}

func uvarintLen(z uint64) int64 {
	b := bits.Len64(z)
	n := b / 7
	if b%7 != 0 {
		n++
	}
	return int64(n)
}

// MaxPayloadSize returns the maximum payload size.
// This is the size of the largest payload that can be sent.
// The result of MaxPayloadSize is always less than or equal to MaxMessageSize.
func (m *Messenger) MaxPayloadSize() int64 {
	return m.MaxMessageSize() - uvarintLen(m.maxSize) - int64(m.hashSize)
}

// HashFunc returns the hash function the Messenger was created with.
func (m *Messenger) HashFunc() HashFunc {
	return m.hashfn
}

func (m *Messenger) readTooLarge(usize uint64) error {
	if usize > math.MaxInt64 {
		return fmt.Errorf("message of %d bytes exceeds max int64 (%d)",
			usize, math.MaxInt64)
	}

	if usize < uint64(m.hashSize) {
		return fmt.Errorf("message of %d bytes is too small to contain a checksum (%d bytes)",
			usize, m.hashSize)
	}

	if m.maxSize == 0 {
		return nil
	}

	prefix := uvarintLen(usize)
	if usize+uint64(prefix) > m.maxSize {
		return fmt.Errorf("message of %d bytes exceeds max size (%d bytes)",
			usize, m.maxSize)
	}

	return nil
}

// ReadMsgTo reads length, checksum, and payload from r and, if the message is
// valid, stores the payload in the slice p and returns the payload.
//
// If the checksum of the payload does not match when filtered through
// Messenger's hash function, it returns a *VerifyError. This is to prevent
// acceptance of corrupt, spoofed, or otherwise invalid messages (depending on
// the checksum).
//
// If p's length (not capacity) is not large enough to accommodate the message
// payload, a large enough byte slice is allocated to hold it.
//
// Too-small and too-large messages will also return errors.
// All other errors arise from reading from r.
func (m *Messenger) ReadMsgTo(p []byte, r io.Reader) ([]byte, error) {
	if m.maxSize > 0 {
		r = &io.LimitedReader{
			R: r,
			N: int64(m.maxSize),
		}
	}

	h := m.hashfn()
	hashReader := io.TeeReader(r, h)

	// Read size
	usize, err := binary.ReadUvarint(asByteReader(hashReader))
	if err != nil {
		return nil, err
	}

	if err := m.readTooLarge(usize); err != nil {
		return nil, err
	}

	// Read checksum
	checksum := make([]byte, m.hashSize)
	if _, err := io.ReadFull(r, checksum); err != nil {
		return nil, unexpectedEOF(err)
	}

	// Resize or allocate payload buffer
	// NOTE: On 32-bit hosts, there is a possibility of truncating the
	// message size here if the maximum message size isn't set low enough.
	payloadSize := int(usize) - m.hashSize
	if len(p) < payloadSize {
		p = make([]byte, payloadSize)
	} else {
		p = p[:payloadSize]
	}

	// Read and hash payload
	_, err = io.ReadFull(io.TeeReader(r, h), p)
	if err != nil {
		return nil, unexpectedEOF(err)
	}

	// Compare received and computed checksums
	if recvSum := h.Sum(nil); !hmac.Equal(recvSum, checksum) {
		return nil, &VerifyError{
			Want: checksum,
			Got:  recvSum,
		}
	}

	return p, nil
}

// ReadMsg reads length, checksum, and payload from r.
// This function is identical to ReadMsgTo, except that it will always allocate
// a new byte slice for the message. See ReadMsgTo for more detail.
func (m *Messenger) ReadMsg(r io.Reader) ([]byte, error) {
	return m.ReadMsgTo(nil, r)
}

// WriteMsg writes the payload, p, prefixed by its length and checksum, to the
// writer w.
//
// If the total length of the message (length prefix, checksum, and payload p)
// exceeds the Messenger's maximum message size, then the message is not written
// and WriteMsg returns an error.
//
// All other errors arise from writing to w.
func (m *Messenger) WriteMsg(w io.Writer, p []byte) error {
	var intbuf [10]byte
	intp := intbuf[:]
	msgSize := uint64(m.hashSize) + uint64(len(p))
	intlen := binary.PutUvarint(intp, msgSize)
	intp = intp[:intlen]

	totalSize := uint64(intlen) + msgSize
	if m.maxSize == 0 {
		// Max size not defined
	} else if totalSize > m.maxSize {
		return fmt.Errorf("message of %d bytes (length: %d; checksum: %d; payload: %d) exceeds max size of %d bytes",
			totalSize, intlen, m.hashSize, len(p), m.maxSize)
	}

	// Compute checksum
	h := m.hashfn()
	h.Write(intp) // length bytes
	h.Write(p)    // payload
	checksum := h.Sum(make([]byte, 0, m.hashSize))

	// Write message
	err := writeFull(w, intp, nil)    // length bytes
	err = writeFull(w, checksum, err) // checksum bytes
	err = writeFull(w, p, err)        // payload

	return err
}

func writeFull(w io.Writer, p []byte, err error) error {
	if err != nil {
		return err
	} else if n, err := w.Write(p); err != nil {
		return err
	} else if n < len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// byteReader is a simple combined io.ByteReader/io.Reader just for
// binary.ReadUvarint to be happy.
type byteReader interface {
	io.Reader
	io.ByteReader
}

// simpleByteReader wraps an io.Reader and implements a naive io.ByteReader on
// top of it. It doesn't implement special cases because it will only ever be
// used to wrap a TeeReader and is only expected to read up to 10 bytes.
// Ensuring part of the underlying reader is buffered is more useful than
// mucking with this.
type simpleByteReader struct {
	n int
	io.Reader
}

func asByteReader(r io.Reader) byteReader {
	return &simpleByteReader{Reader: r}
}

func (b *simpleByteReader) ReadByte() (byte, error) {
	var p [1]byte
	_, err := io.ReadFull(b.Reader, p[:])
	if err == nil {
		b.n++
	} else if b.n > 0 {
		err = unexpectedEOF(err)
	}
	return p[0], err
}
