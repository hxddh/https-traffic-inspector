package rules

import (
	"errors"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
)

// Recorded answers requests from a record: a request gets the response
// recorded for the same method, path and query parameter names, in the order
// they were recorded, wrapping around. It backs --mock-from and
// "httpmon mock".
type Recorded struct {
	byKey map[string][]*exchange.Exchange
	next  map[string]int
	mu    sync.Mutex
	// ignoreHost matches on path alone, for a server that clients reach at
	// its own address.
	ignoreHost bool
}

// LoadRecorded reads the exchanges of a record that have a response.
func LoadRecorded(path string, ignoreHost bool) (*Recorded, error) {
	return LoadRecordedFiles([]string{path}, ignoreHost)
}

// LoadRecordedFiles reads a session's segments, oldest first.
func LoadRecordedFiles(paths []string, ignoreHost bool) (*Recorded, error) {
	r := &Recorded{byKey: map[string][]*exchange.Exchange{}, next: map[string]int{}, ignoreHost: ignoreHost}
	var all []*exchange.Exchange
	for i, path := range paths {
		if err := readResponses(path, i, &all); err != nil {
			return nil, err
		}
	}
	// Recorded order: the order of the files, then of ids within each.
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].Ref < all[j].Ref || all[i].Ref == all[j].Ref && all[i].ID < all[j].ID
	})
	for _, e := range all {
		u, err := url.Parse(e.URL)
		if err != nil {
			continue
		}
		k := r.key(e.Method, u.Host, u.Path, u.RawQuery)
		r.byKey[k] = append(r.byKey[k], e)
	}
	return r, nil
}

func (r *Recorded) key(method, host, path, rawQuery string) string {
	q, _ := url.ParseQuery(rawQuery)
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	h := strings.ToLower(host)
	if r.ignoreHost {
		h = ""
	}
	h = strings.TrimSuffix(strings.TrimSuffix(h, ":443"), ":80")
	return method + " " + h + path + "?" + strings.Join(names, "&")
}

// Len is the number of recorded responses.
func (r *Recorded) Len() int {
	n := 0
	for _, v := range r.byKey {
		n += len(v)
	}
	return n
}

func readResponses(path string, file int, all *[]*exchange.Exchange) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rd := exchange.NewReader(f)
	for {
		e, err := rd.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if e.Response != nil && e.Error == nil && e.WebSocket == nil {
			e.Ref = file
			*all = append(*all, e)
		}
	}
}

// Lookup returns the next recorded exchange for a request, or nil.
func (r *Recorded) Lookup(method, host, path, rawQuery string) *exchange.Exchange {
	if r == nil {
		return nil
	}
	k := r.key(method, host, path, rawQuery)
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.byKey[k]
	if len(list) == 0 {
		return nil
	}
	i := r.next[k] % len(list)
	r.next[k]++
	return list[i]
}

// Endpoints lists what the record can answer, for a helpful 404.
func (r *Recorded) Endpoints() []string {
	out := make([]string, 0, len(r.byKey))
	for k := range r.byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
