package hmsg_test

import (
	"bytes"
	"crypto/sha1"
	"fmt"

	"go.spiff.io/hmsg"
)

func ExampleMessenger() {
	// Allocate a new Messenger for sending messages up to 1000 bytes long.
	//
	// For this, we'll use HMAC-SHA1 to verify messages, but you can also
	// use plain MD5, CRC32, SHA1, or other hashes.
	m, err := hmsg.NewMessenger(1000, hmsg.HMAC("super-secret-key", sha1.New))
	if err != nil {
		panic(fmt.Sprint("Error creating messenger: ", err))
	}

	const message = "Hello, World"

	// Create a buffer to write a message -- in practice, this might be
	// a TCP connection or something similar.
	buf := &bytes.Buffer{}

	// Write a message to the buffer. The message includes its length and
	// checksum, which is used to verify the message when we read it.
	if err := m.WriteMsg(buf, []byte(message)); err != nil {
		panic(fmt.Sprint("Error writing message: ", err))
	}

	// Read the message. If it had been tampered with, ReadMsg would return
	// a *VerifyError.
	received, err := m.ReadMsg(buf)
	if err != nil {
		panic(fmt.Sprint("Error receiving message: ", err))
	}

	fmt.Printf("Received message: %q\n", string(received))

	// Output:
	// Received message: "Hello, World"
}
