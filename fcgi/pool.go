package fcgi

import (
	"bufio"
	"bytes"
	"sync"
)

// Pools for reusing hot-path allocations across requests.

var bufioWriterPool = sync.Pool{
	New: func() any {
		return bufio.NewWriter(nil)
	},
}

var stdinBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxContentSize)
		return &buf
	},
}

var stdoutBufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

var stderrBufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

var recordBufPool = sync.Pool{
	New: func() any {
		// Max record content + padding: 65535 + 7
		buf := make([]byte, maxContentSize+recordAlignment-1)
		return &buf
	},
}

var bufioReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReader(nil)
	},
}
