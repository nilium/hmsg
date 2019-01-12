// This is an example message reader/writer with length prefixes and digests
// (in the example's case, using hmac-sha1) to try to confirm that the entire
// correct message was read.

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"hash/crc64"
	"io"
	"io/ioutil"
	"log"
	"os"

	"go.spiff.io/hmsg"
)

func main() {
	log.SetFlags(0)

	var (
		maxSize  = flag.Int64("m", 0, "Max payload `size` (not including length and checksum)")
		decode   = flag.Bool("d", false, "Read messages from stdin")
		key      = flag.String("k", "", "Message `key` (HMAC hash if non-empty)")
		hashname = flag.String("f", "sha1", "Hash `function` (sha1, sha256, md5, crc64, null)")
	)
	flag.Parse()

	hashfn := namedHashFunc(*hashname)
	if *key != "" {
		hashfn = hmsg.HMAC(*key, hashfn)
	}

	var maxMsgSize int64
	if maxSize != nil && *maxSize > 0 {
		maxMsgSize = hmsg.MaxMessageSize(*maxSize, hashfn)
	}

	mr, err := hmsg.NewMessenger(maxMsgSize, hashfn)
	if err != nil {
		log.Fatalf("Cannot create messenger: %v", err)
	}

	if *decode {
		err = ReadMessages(os.Stdin, mr)
	} else {
		err = writeMessages(mr)
	}

	if err != nil && err != io.EOF {
		log.Fatalf("Error: %v\n", err)
	}
}

func namedHashFunc(name string) hmsg.HashFunc {
	switch *hashname {
	case "sha1":
		return sha1.New
	case "sha256":
		return sha256.New
	case "md5":
		return md5.New
	case "crc64":
		isoTable := crc64.MakeTable(crc64.ISO)
		return func() hash.Hash { return crc64.New(isoTable) }
	case "null":
		return hmsg.NullHash
	default:
		log.Fatalf("unrecognized hash function: %s", *hashname)
		panic("unreachable")
	}
}

func writeMessages(mr *hmsg.Messenger) (err error) {
	msgs := flag.Args()
	if len(msgs) == 0 {
		msgs, err = readerMessage(os.Stdin)
		if err != nil {
			return err
		}
	}
	return WriteMessages(os.Stdout, mr, msgs)
}

func readerMessage(r io.Reader) ([]string, error) {
	var msg []byte
	msg, err = ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	return []string{string(msg)}
}

func WriteMessages(w io.Writer, mr *hmsg.Messenger, messages []string) error {
	for _, msg := range messages {
		err := mr.WriteMsg(w, []byte(msg))
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadMessages(r io.Reader, mr *hmsg.Messenger) error {
	next := false
	for {
		msg, err := mr.ReadMsg(r)
		if err != nil {
			return err
		}
		os.Stdout.Write(msg)
		if next || isTTY() {
			fmt.Print("\n")
		}
		next = true
	}
}

// isTTY attempts to determine whether the current stdout refers to a terminal.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		log.Println("Error getting Stat of os.Stdout:", err)
		return true // Assume human readable
	}
	return (fi.Mode() & os.ModeNamedPipe) != os.ModeNamedPipe
}
