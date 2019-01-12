package hmsg

import (
	"crypto/hmac"
	"hash"
)

// HashFunc is a function that returns a new hash.Hash for use in a Messenger.
// Returned hashes are not reused.
type HashFunc func() hash.Hash

// HMAC returns a HashFunc for an HMAC hash function with a given key and hash
// function.
func HMAC(key string, hashfn HashFunc) HashFunc {
	bkey := []byte(key)
	return func() hash.Hash {
		return hmac.New(hashfn, bkey)
	}
}

// NullHash is a hash function with no size and no hash.
// It can be used in debugging to accept a hash as part of a message, but should
// not be used for real messages.
func NullHash() hash.Hash {
	return nullHasher{}
}

// nullHasher is an implementation of hash.Hash that produces a zero-length
// checksum (it does not hash anything at all).
type nullHasher struct{}

func (nullHasher) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (nullHasher) Size() int           { return 0 }
func (nullHasher) Reset()              {}
func (nullHasher) BlockSize() int      { return 1 }
func (nullHasher) Sum(h []byte) []byte { return h[:0] }
