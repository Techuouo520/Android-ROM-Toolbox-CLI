package progress

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	barWidth    = 24
	minBarWidth = 8
)

type Item struct {
	Name  string
	Bytes uint64
	Units int
}

type Snapshot struct {
	Bytes      uint64
	TotalBytes uint64
	Done       int
	Items      int
}

type Tracker struct {
	index     map[string]int
	items     []Item
	completed []atomic.Int64
	done      []atomic.Bool
	total     uint64
}

func NewTracker(items []Item) *Tracker {
	tracker := &Tracker{index: make(map[string]int, len(items)), items: items, completed: make([]atomic.Int64, len(items)), done: make([]atomic.Bool, len(items))}
	for position, item := range items {
		tracker.index[item.Name] = position
		tracker.total += item.Bytes
	}
	return tracker
}

func (tracker *Tracker) Set(name string, completed int, done bool) {
	position, ok := tracker.index[name]
	if !ok {
		return
	}
	tracker.completed[position].Store(int64(completed))
	if done {
		tracker.done[position].Store(true)
	}
}

func (tracker *Tracker) Snapshot() Snapshot {
	snapshot := Snapshot{TotalBytes: tracker.total, Items: len(tracker.items)}
	for position, item := range tracker.items {
		if tracker.done[position].Load() {
			snapshot.Bytes += item.Bytes
			snapshot.Done++
			continue
		}
		if item.Units > 0 {
			completed := min(uint64(max(tracker.completed[position].Load(), 0)), uint64(item.Units))
			snapshot.Bytes += item.Bytes * completed / uint64(item.Units)
		}
	}
	return snapshot
}

type Source interface {
	Snapshot() Snapshot
}

type Gauge struct {
	bytes atomic.Uint64
	total atomic.Uint64
	done  atomic.Uint64
	items atomic.Uint64
}

func (gauge *Gauge) Set(bytes, total, done, items uint64) {
	gauge.total.Store(total)
	gauge.items.Store(items)
	gauge.bytes.Store(bytes)
	gauge.done.Store(done)
}

func (gauge *Gauge) Snapshot() Snapshot {
	return Snapshot{Bytes: gauge.bytes.Load(), TotalBytes: gauge.total.Load(), Done: int(gauge.done.Load()), Items: int(gauge.items.Load())}
}

// ReportWriter consumes native "progress <bytes> <total> <done> <items>" lines and forwards all other output.
type ReportWriter struct {
	gauge   *Gauge
	output  io.Writer
	pending []byte
}

func NewReportWriter(gauge *Gauge, output io.Writer) *ReportWriter {
	return &ReportWriter{gauge: gauge, output: output}
}

func (writer *ReportWriter) Write(data []byte) (int, error) {
	writer.pending = append(writer.pending, data...)
	for {
		index := bytes.IndexByte(writer.pending, '\n')
		if index < 0 {
			return len(data), nil
		}
		line := writer.pending[:index+1]
		writer.pending = writer.pending[index+1:]
		if !writer.parse(line) {
			if _, err := writer.output.Write(line); err != nil {
				return 0, err
			}
		}
	}
}

func (writer *ReportWriter) Flush() error {
	if len(writer.pending) == 0 {
		return nil
	}
	_, err := writer.output.Write(writer.pending)
	writer.pending = nil
	return err
}

func (writer *ReportWriter) parse(line []byte) bool {
	fields := strings.Fields(string(line))
	if len(fields) != 5 || fields[0] != "progress" {
		return false
	}
	var values [4]uint64
	for position := range values {
		value, err := strconv.ParseUint(fields[position+1], 10, 64)
		if err != nil {
			return false
		}
		values[position] = value
	}
	writer.gauge.Set(values[0], values[1], values[2], values[3])
	return true
}

// Format renders the full-width progress line.
func Format(snapshot Snapshot, elapsed time.Duration) string {
	return FormatWidth(snapshot, elapsed, 0)
}

// FormatWidth fits the line into columns terminal cells, 0 meaning unlimited: the bar shrinks, then goes, then the text is cut.
func FormatWidth(snapshot Snapshot, elapsed time.Duration, columns int) string {
	ratio := 0.0
	if snapshot.TotalBytes > 0 {
		ratio = min(float64(snapshot.Bytes)/float64(snapshot.TotalBytes), 1)
	} else if snapshot.Items > 0 && snapshot.Done >= snapshot.Items {
		ratio = 1
	}
	rate := 0.0
	if seconds := elapsed.Seconds(); seconds > 0 {
		rate = float64(snapshot.Bytes) / seconds
	}
	eta := "--"
	if ratio >= 1 {
		eta = "0s"
	} else if rate > 0 {
		eta = time.Duration(float64(snapshot.TotalBytes-snapshot.Bytes) / rate * float64(time.Second)).Round(time.Second).String()
	}
	head := fmt.Sprintf("%5.1f%%", ratio*100)
	tail := fmt.Sprintf("%s %6.1f MiB/s ETA %s %d/%d", sizeText(snapshot.Bytes, snapshot.TotalBytes), rate/(1<<20), eta, snapshot.Done, snapshot.Items)
	width := barWidth
	if columns > 0 {
		// One cell stays free so the cursor never wraps; a wrapped line cannot be redrawn with a carriage return.
		width = min(barWidth, columns-1-len(head)-len(tail)-4)
	}
	if width < minBarWidth {
		line := head + " " + tail
		if columns > 0 && len(line) > columns-1 {
			line = line[:max(columns-1, 0)]
		}
		return line
	}
	filled := int(ratio * float64(width))
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
	if filled > 0 && filled < width {
		bar = strings.Repeat("=", filled-1) + ">" + strings.Repeat(" ", width-filled)
	}
	return head + " [" + bar + "] " + tail
}

// terminalColumns reports the width of the terminal behind writer, or 0 when it is unknown.
func terminalColumns(writer io.Writer) int {
	if file, ok := writer.(*os.File); ok {
		if columns := consoleColumns(file.Fd()); columns > 0 {
			return columns
		}
	}
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns > 0 {
		return columns
	}
	return 0
}

func sizeText(current, total uint64) string {
	if total >= 1<<30 {
		return fmt.Sprintf("%.2f/%.2f GiB", float64(current)/(1<<30), float64(total)/(1<<30))
	}
	return fmt.Sprintf("%.1f/%.1f MiB", float64(current)/(1<<20), float64(total)/(1<<20))
}

type Bar struct {
	writer   io.Writer
	source   Source
	started  time.Time
	width    int
	stop     chan struct{}
	finished chan error
}

func Start(writer io.Writer, source Source, interval time.Duration) *Bar {
	bar := &Bar{writer: writer, source: source, started: time.Now(), stop: make(chan struct{}), finished: make(chan error, 1)}
	go bar.run(interval)
	return bar
}

func (bar *Bar) Stop() error {
	close(bar.stop)
	return <-bar.finished
}

func (bar *Bar) run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := bar.draw(); err != nil {
			bar.finished <- err
			return
		}
		select {
		case <-ticker.C:
		case <-bar.stop:
			err := bar.draw()
			if err == nil {
				_, err = io.WriteString(bar.writer, "\n")
			}
			bar.finished <- err
			return
		}
	}
}

func (bar *Bar) draw() error {
	// Measured on every draw so resizing the terminal mid-run keeps the line on one row.
	columns := terminalColumns(bar.writer)
	line := FormatWidth(bar.source.Snapshot(), time.Since(bar.started), columns)
	padding := max(bar.width-len(line), 0)
	if columns > 0 {
		padding = min(padding, max(columns-1-len(line), 0))
	}
	bar.width = len(line)
	_, err := io.WriteString(bar.writer, "\r"+line+strings.Repeat(" ", padding))
	return err
}
