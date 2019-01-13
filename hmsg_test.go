package hmsg_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"hash"
	"hash/fnv"
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

// Benchmarks

// benchmarkMsg here is intended to be a reasonably long but inside what I am
// assuming is a typical MTU of like 1500.
const benchmarkMsg = `{"data":{"name":"erlang","version":"21.2","revision":1,"architecture":"x86_64","build_date":"2018-12-16T16:39:00Z","build_options":"~x11 ","filename_sha256":"c7da634d2b2a9489abcc7a5af5b07dcaa6b18f2f751133d0f9bac4492bf8178b","filename_size":35292264,"homepage":"http://www.erlang.org/","installed_size":99894053,"license":"Apache-2.0","maintainer":"Leah Neukirchen \u003cleah@vuxu.org\u003e","short_desc":"Concurrent functional programming language developed by Ericsson","source_revisions":"erlang:2dda58cbaa","run_depends":["glibc\u003e=2.28_1","ncurses-libs\u003e=5.8_1","zlib\u003e=1.2.3_1","libodbc\u003e=2.3.1_1","libcrypto44\u003e=2.8.2_1"],"shlib_requires":["libm.so.6","libc.so.6","libutil.so.1","librt.so.1","libdl.so.2","libncursesw.so.6","libz.so.1","libpthread.so.0","libodbc.so.2","libcrypto.so.44"]}}`

func benchmarkHash() hash.Hash {
	return fnv.New64a()
}

// Note: All benchmarks currently use FNV1-a 64-bit hashes. This has an impact
// on their timing and is intended to get a better feel for normal use.

// BenchmarkSimpleWrite tests writing a message to ioutil.Discard.
func BenchmarkSimpleWrite(b *testing.B) {
	m, err := hmsg.NewMessenger(1000, benchmarkHash)
	if err != nil {
		b.Fatalf("Unable to create messenger: %v", err)
	}

	msg := []byte(benchmarkMsg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.WriteMsg(ioutil.Discard, msg); err != nil {
			b.Fatalf("WriteMsg(..) = %#v; expected no error", err)
		}
	}
}

// BenchmarkSimpleRead is a test of using ReadMsg and allowing Messenger to
// allocate an appropriately sized buffer each time.
func BenchmarkSimpleRead(b *testing.B) {
	m, err := hmsg.NewMessenger(1000, benchmarkHash)
	if err != nil {
		b.Fatalf("Unable to create messenger: %v", err)
	}

	var buf bytes.Buffer
	if err := m.WriteMsg(&buf, []byte(benchmarkMsg)); err != nil {
		b.Fatalf("WriteMsg(..) error = %#v; expected no error", err)
	}

	msg := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.ReadMsg(bytes.NewReader(msg)); err != nil {
			b.Fatalf("ReadMsg(..) = %#v; expected no error", err)
		}
	}
}

// BenchmarkBufferedRead tests reading into a preallocated buffer to see whether
// this impacts performance or if the majority of time spent is elsewhere.
func BenchmarkBufferedRead(b *testing.B) {
	m, err := hmsg.NewMessenger(1000, benchmarkHash)
	if err != nil {
		b.Fatalf("Unable to create messenger: %v", err)
	}

	var buf bytes.Buffer
	if err := m.WriteMsg(&buf, []byte(benchmarkMsg)); err != nil {
		b.Fatalf("WriteMsg(..) error = %#v; expected no error", err)
	}

	msg := buf.Bytes()
	back := make([]byte, m.MaxPayloadSize())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := m.ReadMsgTo(back, bytes.NewReader(msg))
		if err != nil {
			b.Fatalf("ReadMsgTo(..) = %#v; expected no error", err)
		}
		back = p
	}
}

// BenchmarkBufferedUnlimitedRead tests reading ito a preallocated buffer with
// no maximum message size. This prevents allocation of a LimitedReader (which
// could be removed later, but is in there as a basic safety measure).
func BenchmarkBufferedUnlimitedRead(b *testing.B) {
	m, err := hmsg.NewMessenger(0, benchmarkHash)
	if err != nil {
		b.Fatalf("Unable to create messenger: %v", err)
	}

	var buf bytes.Buffer
	if err := m.WriteMsg(&buf, []byte(benchmarkMsg)); err != nil {
		b.Fatalf("WriteMsg(..) error = %#v; expected no error", err)
	}

	msg := buf.Bytes()
	back := make([]byte, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := m.ReadMsgTo(back, bytes.NewReader(msg))
		if err != nil {
			b.Fatalf("ReadMsgTo(..) = %#v; expected no error", err)
		}
		back = p
	}
}
