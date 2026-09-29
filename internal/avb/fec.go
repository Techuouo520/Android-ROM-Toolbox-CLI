package avb

import (
	"fmt"
	"io"
	"sync"
)

// FECBlockSize is the libfec interleaving unit; codeword c takes byte c of every rounds*FECBlockSize row.
const FECBlockSize = 4096

// rsCode holds libfec's Reed-Solomon code (GF(2^8), polynomial 0x11d, first root 0, primitive element 1) as
// per-position lookup tables, since parity is linear in the data: tables[k][j][x] = x * parity_j(unit vector k).
type rsCode struct {
	roots  int
	tables [][][256]byte
}

func newRSCode(roots int) (*rsCode, error) {
	if roots < 2 || roots > 24 {
		return nil, fmt.Errorf("unsupported FEC root count %d", roots)
	}
	var alphaTo [256]byte
	var indexOf [256]int
	indexOf[0] = 255
	for index, value := 0, 1; index < 255; index++ {
		indexOf[value], alphaTo[index] = index, byte(value)
		if value <<= 1; value&0x100 != 0 {
			value ^= 0x11d
		}
	}
	// Karn's init_rs_char with fcr 0 and prim 1, converted to index form.
	generator := make([]int, roots+1)
	generator[0] = 1
	for index := 0; index < roots; index++ {
		generator[index+1] = 1
		for position := index; position > 0; position-- {
			if generator[position] != 0 {
				generator[position] = generator[position-1] ^ int(alphaTo[(indexOf[generator[position]]+index)%255])
			} else {
				generator[position] = generator[position-1]
			}
		}
		generator[0] = int(alphaTo[(indexOf[generator[0]]+index)%255])
	}
	for index := range generator {
		generator[index] = indexOf[generator[index]]
	}
	multiply := func(a, b byte) byte {
		if a == 0 || b == 0 {
			return 0
		}
		return alphaTo[(indexOf[a]+indexOf[b])%255]
	}
	data := 255 - roots
	code := &rsCode{roots: roots, tables: make([][][256]byte, data)}
	parity := make([]byte, roots)
	for position := range data {
		clear(parity)
		// Karn's encode_rs_char on the unit vector with a single 1 at position.
		for index := range data {
			var symbol byte
			if index == position {
				symbol = 1
			}
			feedback := indexOf[symbol^parity[0]]
			if feedback != 255 {
				for root := 1; root < roots; root++ {
					parity[root] ^= alphaTo[(feedback+generator[roots-root])%255]
				}
			}
			copy(parity, parity[1:])
			parity[roots-1] = 0
			if feedback != 255 {
				parity[roots-1] = alphaTo[(feedback+generator[0])%255]
			}
		}
		code.tables[position] = make([][256]byte, roots)
		for root, coefficient := range parity {
			for value := range 256 {
				code.tables[position][root][value] = multiply(byte(value), coefficient)
			}
		}
	}
	return code, nil
}

// FECSize returns the parity bytes libfec produces for size input bytes.
func FECSize(size int64, roots int) int64 {
	return fecRounds(size, roots) * FECBlockSize * int64(roots)
}

func fecRounds(size int64, roots int) int64 {
	blocks := (size + FECBlockSize - 1) / FECBlockSize
	data := int64(255 - roots)
	return (blocks + data - 1) / data
}

// encodeFEC computes libfec parity for the first size bytes of input, reading it once in row order and
// splitting every row across workers; parity for codeword c lands at c*roots.
func encodeFEC(input io.ReaderAt, size int64, roots, workers int) ([]byte, error) {
	code, err := newRSCode(roots)
	if err != nil {
		return nil, err
	}
	row := fecRounds(size, roots) * FECBlockSize
	parity := make([]byte, row*int64(roots))
	type chunk struct {
		data []byte
		err  error
	}
	rows := make(chan chunk, 1)
	free := make(chan []byte, 2)
	free <- make([]byte, row)
	free <- make([]byte, row)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(rows)
		for position := range int64(len(code.tables)) {
			start := position * row
			if start >= size {
				return
			}
			var buffer []byte
			select {
			case buffer = <-free:
			case <-stop:
				return
			}
			buffer = buffer[:min(row, size-start)]
			count, readErr := input.ReadAt(buffer, start)
			if readErr == io.EOF && count == len(buffer) {
				readErr = nil
			}
			select {
			case rows <- chunk{data: buffer, err: readErr}:
			case <-stop:
				return
			}
			if readErr != nil {
				return
			}
		}
	}()
	const span = 64 << 10
	workers = max(workers, 1)
	for position := 0; ; position++ {
		next, ok := <-rows
		if !ok {
			break
		}
		if next.err != nil {
			return nil, fmt.Errorf("read FEC input: %w", next.err)
		}
		tables := code.tables[position]
		var group sync.WaitGroup
		pieces := make(chan int, (len(next.data)+span-1)/span)
		for start := 0; start < len(next.data); start += span {
			pieces <- start
		}
		close(pieces)
		for range min(workers, cap(pieces)) {
			group.Add(1)
			go func() {
				defer group.Done()
				for start := range pieces {
					data := next.data[start:min(start+span, len(next.data))]
					if roots == 2 {
						low, high := &tables[0], &tables[1]
						out := parity[2*start : 2*(start+len(data))]
						for index, value := range data {
							out[2*index] ^= low[value]
							out[2*index+1] ^= high[value]
						}
						continue
					}
					out := parity[roots*start : roots*(start+len(data))]
					for index, value := range data {
						if value == 0 {
							continue
						}
						for root := range roots {
							out[roots*index+root] ^= tables[root][value]
						}
					}
				}
			}()
		}
		group.Wait()
		free <- next.data[:cap(next.data)]
	}
	return parity, nil
}
