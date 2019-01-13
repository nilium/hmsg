package hmsg_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"

	"go.spiff.io/hmsg"
)

func testMessengers(maxSize int64, fn func(*testing.T, io.ReadWriter, *hmsg.Messenger)) func(t *testing.T) {
	type Case struct {
		Name string
		Fun  hmsg.HashFunc
	}

	fns := []Case{
		{"Null", hmsg.NullHash},
		{"SHA1", sha1.New},
		{"HMAC", hmsg.HMAC("some-key", md5.New)},
	}

	return func(t *testing.T) {
		for _, c := range fns {
			c := c
			t.Run(c.Name, func(t *testing.T) {
				m, err := hmsg.NewMessenger(maxSize, c.Fun)
				if err != nil {
					t.Fatalf("Cannot create messenger: %v", err)
				}
				fn(t, new(bytes.Buffer), m)
			})
		}
	}
}

func TestMaxPayloadSize(t *testing.T) {
	for i := 43; i < 4043; i += 1000 {
		t.Run(strconv.Itoa(i), testMessengers(int64(i), func(t *testing.T, rw io.ReadWriter, m *hmsg.Messenger) {
			tooLong := testMessage(m.MaxPayloadSize() + 1)
			err := m.WriteMsg(rw, tooLong)
			if err == nil {
				t.Fatalf("WriteMsg(msg(%d)) error = %#v; expected error", len(tooLong), err)
			}

			msg := testMessage(m.MaxPayloadSize())
			err = m.WriteMsg(ioutil.Discard, msg)
			if err != nil {
				t.Fatalf("WriteMsg(msg(%d)) error = %#v; expected no error", len(msg), err)
			}
		}))
	}
}

func TestReadWrite(t *testing.T) {
	const testMsg = "Hello, Messenger"
	m, err := hmsg.NewMessenger(0, md5.New)
	if err != nil {
		t.Fatalf("Cannot create messenger: %v", err)
	}

	buf := new(bytes.Buffer)
	msg := []byte(testMsg)
	if err := m.WriteMsg(buf, msg); err != nil {
		t.Fatalf("Write(%q) error = %v; expected no error", msg, err)
	}

	if string(msg) != testMsg {
		t.Fatalf("Write(%q) modified message; got %q", testMsg, msg)
	}

	msg, err = m.ReadMsg(buf)
	if err != nil {
		t.Fatalf("ReadMsg() error = %v; expected no error", err)
	}

	if string(msg) != testMsg {
		t.Fatalf("ReadMsg() message = %q; expected %q", testMsg, msg)
	}
}

func TestShortReads(t *testing.T) {
	const testMsg = `
	This is intended to be long enough of a message that it has a multi-byte
	lenth prefix, which means it needs to exceed 128 bytes, so here we are.
	`
	m, err := hmsg.NewMessenger(hmsg.MaxMessageSize(int64(len(testMsg)), md5.New), md5.New)
	if err != nil {
		t.Fatalf("Cannot create messenger: %v", err)
	}

	buf := new(bytes.Buffer)
	msg := []byte(testMsg)
	if err := m.WriteMsg(buf, msg); err != nil {
		t.Fatalf("Write(%q) error = %v; expected no error", msg, err)
	}

	if string(msg) != testMsg {
		t.Fatalf("Write(%q) modified message; got %q", testMsg, msg)
	}

	buffer := func(n int) io.Reader {
		return bytes.NewReader(buf.Bytes()[:n])
	}

	// EOF in the middle of length
	if _, err := m.ReadMsg(buffer(1)); err != io.ErrUnexpectedEOF {
		t.Errorf("ReadMsg([:1]) = %#v; expected %#v", err, io.ErrUnexpectedEOF)
	}

	// EOF in the middle of digest
	if _, err := m.ReadMsg(buffer(4)); err != io.ErrUnexpectedEOF {
		t.Errorf("ReadMsg([:1]) = %#v; expected %#v", err, io.ErrUnexpectedEOF)
	}

	// EOF just before end of payload
	if _, err := m.ReadMsg(buffer(buf.Len() - 1)); err != io.ErrUnexpectedEOF {
		t.Errorf("ReadMsg([:1]) = %#v; expected %#v", err, io.ErrUnexpectedEOF)
	}
}

func TestImpossibleMessageSize(t *testing.T) {
	if _, err := hmsg.NewMessenger(1, hmsg.NullHash); err == nil {
		t.Fatalf("NewMessenger(1, NullHash) error = %v; expected error", err)
	}
}

func TestNoHashFunc(t *testing.T) {
	if _, err := hmsg.NewMessenger(0, nil); err == nil {
		t.Fatalf("NewMessenger(0, nil) error = %v; expected error", err)
	}
}

func TestVeryLargeMessage(t *testing.T) {
	var msg = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00"
	m, err := hmsg.NewMessenger(0, hmsg.NullHash)
	if err != nil {
		t.Fatalf("NewMessenger(0, NullHash) error = %v; expected no error", err)
	}

	_, err = m.ReadMsg(strings.NewReader(msg))
	switch err {
	case io.ErrUnexpectedEOF, nil:
		t.Fatalf("ReadMsg(..) error = %#v; expected length error", err)
	default:
		t.Logf("ReadMsg(..) error = %#v", err)
	}
}

func TestTooSmallMessage(t *testing.T) {
	var msg = "\x01\x00\x00\x00\x00\x00"
	m, err := hmsg.NewMessenger(0, md5.New)
	if err != nil {
		t.Fatalf("NewMessenger(0, NullHash) error = %v; expected no error", err)
	}

	_, err = m.ReadMsg(strings.NewReader(msg))
	switch err {
	case io.ErrUnexpectedEOF, nil:
		t.Fatalf("ReadMsg(..) error = %#v; expected length error", err)
	default:
		t.Logf("ReadMsg(..) error = %#v", err)
	}
}

func TestTooLongMessage(t *testing.T) {
	var msg = "\x04\x00\x00\x00\x00"
	m, err := hmsg.NewMessenger(4, hmsg.NullHash)
	if err != nil {
		t.Fatalf("NewMessenger(0, NullHash) error = %v; expected no error", err)
	}

	_, err = m.ReadMsg(strings.NewReader(msg))
	switch err {
	case io.ErrUnexpectedEOF, nil:
		t.Fatalf("ReadMsg(..) error = %#v; expected length error", err)
	default:
		t.Logf("ReadMsg(..) error = %#v", err)
	}
}

func TestHashMismatch(t *testing.T) {
	var msg = "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00foo bar baz"
	m, err := hmsg.NewMessenger(0, md5.New)
	if err != nil {
		t.Fatalf("NewMessenger(0, NullHash) error = %v; expected no error", err)
	}

	_, err = m.ReadMsg(strings.NewReader(msg))
	switch err {
	case io.ErrUnexpectedEOF, nil:
		t.Fatalf("ReadMsg(..) error = %#v; expected length error", err)
	default:
		if !hmsg.IsVerifyError(err) {
			t.Fatalf("ReadMsg(..) error = %#v; expected *VerifyError", err)
		}
		t.Logf("ReadMsg(..) error = %#v", err)
	}
}

func testMessage(n int64) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}
