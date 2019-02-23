hmsg
====
<!-- BADGES! -->
[![GoDoc](https://godoc.org/go.spiff.io/hmsg?status.svg)](https://godoc.org/go.spiff.io/hmsg)
[![Go Report Card](https://goreportcard.com/badge/go.spiff.io/hmsg)](https://goreportcard.com/report/go.spiff.io/hmsg)
[![CircleCI](https://circleci.com/gh/nilium/hmsg/tree/master.svg?style=svg)](https://circleci.com/gh/nilium/hmsg/tree/master)
[![codecov](https://codecov.io/gh/nilium/hmsg/branch/master/graph/badge.svg)](https://codecov.io/gh/nilium/hmsg)


hmsg is a library for writing and reading length- and checksum-prefixed
messages. Its primary purpose is to act as a first step in ensuring message
integrity between systems and, to a limited extent, authenticity (assuming you
use an HMAC or similar).


Install
-------

    $ go get go.spiff.io/hmsg


Usage
-----
Almost all interaction with hmsg is done through a Messenger:

```go
hashFun := hmsg.HMAC("some-key", sha1.New)
// Allocate a new Messenger for max-1000-bytes messages with an HMAC-SHA1 hash
m, err := hmsg.NewMessenger(1000, hashFun)
if err != nil {
    // NewMessenger only fails if the max size is too small to hold the hash and
    // length prefixes, or if the hash function is invalid in some way.
    panic(fmt.Errorf("Failed to create messenger: %v", err))
}
```

Once you have a Messenger, you can use it to write and read messages. In
a server, you might use the same messenger across multiple connections (the
Messenger type doesn't have state, so it's safe to share) to read messages
before dispatching them and writing a response message back:

```go
type Server struct {
    messenger *hmsg.Messenger
}

// HandleConn receives messages from a connection, parses them as JSON, and
// dispatches them. If dispatch succeeds, it sends the reply back as a JSON
// message.
func (s *Server) HandleConn(conn net.Conn) error {
    defer conn.Close()
    for {
        p, err := s.messenger.ReadMsg(conn)
        if err != nil {
            return err
        }

        var req Request
        if err = json.Unmarshal(p, &req); err != nil {
            return err
        }

        rep, err := s.Dispatch(&req)
        if err != nil {
            return err
        }

        p, err = json.Marshal(rep)
        if err != nil {
            return err
        }

        if err = s.messenger.WriteMsg(conn, p); err != nil {
            return err
        }
    }
}
```


A similar process would be involved in a client connection as well.


Stability
---------
hmsg is relatively stable but may undergo breaking changes if required. For this
reason, it is recommended you pin uses of hmsg a specific commit. Version tags
may also be available at different points in the project's history.

The hmsg API may undergo breaking changes prior to version 1.0.0. After 1.0.0,
all breaking changes will involve a major version change (i.e., to make breaking
changes after 1.0.0, hmsg would need to release 2.0.0).


License
-------
hmsg is licensed under the MIT license.

<!-- vim: set tw=80 sw=4 ts=4 et : -->
