package payload

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"slices"
	"sync"

	"github.com/ssut/payload-dumper-go/chromeos_update_engine"
)

var zeroChunk = make([]byte, 1<<20)

type hashSegment struct {
	start  uint64
	length uint64
	op     int
	offset uint64
}

// streamHasher feeds operation outputs into the partition SHA-256 in image offset order while operations finish out of order.
type streamHasher struct {
	mu         sync.Mutex
	cond       *sync.Cond
	digest     hash.Hash
	segments   []hashSegment
	blocking   []int
	opSegments [][]int
	remaining  []int
	data       [][]byte
	release    []func()
	ready      []bool
	next       int
	window     int
	active     bool
}

// newStreamHasher returns nil when destination extents overlap, so the caller must verify by reading the image back.
func newStreamHasher(ops []*chromeos_update_engine.InstallOperation, blockSize, size uint64, window int) *streamHasher {
	var data []hashSegment
	for index, op := range ops {
		var offset uint64
		for _, extent := range op.GetDstExtents() {
			start := extent.GetStartBlock() * blockSize
			length := extent.GetNumBlocks() * blockSize
			if start < size && length > 0 {
				data = append(data, hashSegment{start: start, length: min(length, size-start), op: index, offset: offset})
			}
			offset += length
		}
	}
	slices.SortFunc(data, func(a, b hashSegment) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	})
	h := &streamHasher{digest: sha256.New(), opSegments: make([][]int, len(ops)), remaining: make([]int, len(ops)), data: make([][]byte, len(ops)), release: make([]func(), len(ops)), window: window}
	h.cond = sync.NewCond(&h.mu)
	var cursor uint64
	for _, segment := range data {
		if segment.start < cursor {
			return nil
		}
		if segment.start > cursor {
			h.segments = append(h.segments, hashSegment{start: cursor, length: segment.start - cursor, op: -1})
		}
		h.opSegments[segment.op] = append(h.opSegments[segment.op], len(h.segments))
		h.remaining[segment.op]++
		h.segments = append(h.segments, segment)
		cursor = segment.start + segment.length
	}
	if cursor < size {
		h.segments = append(h.segments, hashSegment{start: cursor, length: size - cursor, op: -1})
	}
	h.ready = make([]bool, len(h.segments))
	h.blocking = make([]int, len(h.segments))
	blocking := len(ops)
	for index := len(h.segments) - 1; index >= 0; index-- {
		if h.segments[index].op < 0 {
			h.ready[index] = true
		} else {
			blocking = h.segments[index].op
		}
		h.blocking[index] = blocking
	}
	return h
}

// wake unblocks waitWindow after context cancellation.
func (h *streamHasher) wake() {
	h.mu.Lock()
	h.cond.Broadcast()
	h.mu.Unlock()
}

// waitWindow bounds buffered out-of-order outputs to window operations past the one blocking the hash cursor.
func (h *streamHasher) waitWindow(ctx context.Context, op int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for h.next < len(h.segments) && op >= h.blocking[h.next]+h.window {
		if err := ctx.Err(); err != nil {
			return err
		}
		h.cond.Wait()
	}
	return ctx.Err()
}

// submit hands over an operation output; nil data means the operation wrote zeros. release is called once the data is hashed.
func (h *streamHasher) submit(op int, data []byte, release func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data[op] = data
	h.release[op] = release
	for _, segment := range h.opSegments[op] {
		h.ready[segment] = true
	}
	if h.remaining[op] == 0 {
		h.releaseOp(op)
	}
	h.drainLocked()
}

func (h *streamHasher) drainLocked() {
	if h.active {
		return
	}
	h.active = true
	for h.next < len(h.segments) && h.ready[h.next] {
		segment := h.segments[h.next]
		var chunk []byte
		if segment.op >= 0 && h.data[segment.op] != nil {
			chunk = h.data[segment.op][segment.offset : segment.offset+segment.length]
		}
		h.mu.Unlock()
		if chunk != nil {
			h.digest.Write(chunk)
		} else {
			for remaining := segment.length; remaining > 0; {
				count := min(remaining, uint64(len(zeroChunk)))
				h.digest.Write(zeroChunk[:count])
				remaining -= count
			}
		}
		h.mu.Lock()
		h.next++
		if segment.op >= 0 {
			h.remaining[segment.op]--
			if h.remaining[segment.op] == 0 {
				h.releaseOp(segment.op)
			}
		}
		h.cond.Broadcast()
	}
	h.active = false
}

func (h *streamHasher) releaseOp(op int) {
	if h.release[op] != nil {
		h.release[op]()
	}
	h.release[op] = nil
	h.data[op] = nil
}

func (h *streamHasher) sum() ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drainLocked()
	if h.next != len(h.segments) {
		return nil, fmt.Errorf("payload: streaming hash stopped at byte %d", h.segments[h.next].start)
	}
	return h.digest.Sum(nil), nil
}
