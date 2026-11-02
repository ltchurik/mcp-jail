package ui

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
)

// maxLine bounds one audit line; longer lines are skipped, not truncated.
const maxLine = 1 << 20

// Filter selects audit events. Empty fields match everything.
type Filter struct {
	Server   string
	Kind     string
	Decision string
	Tool     string
	Host     string
	Since    time.Time
	Until    time.Time
	// Query is a case-insensitive substring match over tool, host, reason
	// and error.
	Query string
}

// Match reports whether e passes the filter.
func (f Filter) Match(e *audit.Event) bool {
	if f.Server != "" && e.Server != f.Server {
		return false
	}
	if f.Kind != "" && e.Kind != f.Kind {
		return false
	}
	if f.Decision != "" && e.Decision != f.Decision {
		return false
	}
	if f.Tool != "" && e.Tool != f.Tool {
		return false
	}
	if f.Host != "" && e.Host != f.Host {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Time.After(f.Until) {
		return false
	}
	if f.Query != "" {
		q := strings.ToLower(f.Query)
		hay := strings.ToLower(e.Tool + " " + e.Host + " " + e.Reason + " " + e.Error + " " + e.Server)
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

// ReadEvents returns the newest `limit` events across the given JSONL files
// that match f, newest first. Unreadable files and unparsable lines are
// skipped; the count of skipped lines is returned so the UI can show it.
func ReadEvents(paths []string, f Filter, limit int) (events []audit.Event, skipped int) {
	if limit <= 0 {
		limit = 500
	}
	for _, p := range paths {
		fh, err := os.Open(p)
		if err != nil {
			continue
		}
		evs, n := scan(fh, f)
		_ = fh.Close()
		skipped += n
		events = append(events, evs...)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	if len(events) > limit {
		events = events[:limit]
	}
	return events, skipped
}

func scan(r io.Reader, f Filter) (out []audit.Event, skipped int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(line, &e); err != nil || e.Time.IsZero() {
			skipped++
			continue
		}
		if f.Match(&e) {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return out, skipped
	}
	return out, skipped
}

// Tailer follows a set of JSONL files from their current end and delivers
// new events. Files that appear later are picked up on the next poll;
// truncated files are re-read from the start.
type Tailer struct {
	paths func() []string
	off   map[string]int64
	rest  map[string][]byte
}

// NewTailer starts at the current end of every file paths() returns now.
func NewTailer(paths func() []string) *Tailer {
	t := &Tailer{paths: paths, off: map[string]int64{}, rest: map[string][]byte{}}
	for _, p := range paths() {
		if st, err := os.Stat(p); err == nil {
			t.off[p] = st.Size()
		}
	}
	return t
}

// Poll returns the events appended since the previous call, oldest first.
func (t *Tailer) Poll() []audit.Event {
	var out []audit.Event
	for _, p := range t.paths() {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		off := t.off[p]
		if st.Size() < off { // truncated or rotated
			off = 0
			t.rest[p] = nil
		}
		if st.Size() == off {
			continue
		}
		fh, err := os.Open(p)
		if err != nil {
			continue
		}
		if _, err := fh.Seek(off, io.SeekStart); err != nil {
			_ = fh.Close()
			continue
		}
		buf, err := io.ReadAll(io.LimitReader(fh, 8<<20))
		_ = fh.Close()
		if err != nil {
			continue
		}
		t.off[p] = off + int64(len(buf))
		data := append(t.rest[p], buf...)
		// keep an unterminated trailing partial line for the next poll
		if i := strings.LastIndexByte(string(data), '\n'); i >= 0 {
			t.rest[p] = append([]byte(nil), data[i+1:]...)
			data = data[:i+1]
		} else {
			t.rest[p] = data
			continue
		}
		evs, _ := scan(strings.NewReader(string(data)), Filter{})
		out = append(out, evs...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}
