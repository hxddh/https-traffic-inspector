package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hxddh/https-traffic-inspector/v5/internal/body"
	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
	"github.com/hxddh/https-traffic-inspector/v5/internal/store"
)

// TestPerfBudget guards the cost of going through httpmon: the latency it
// adds to a request and the rate it sustains. The budgets are several times
// what was measured (+0.26 ms median, 9.2k requests/s at 50 clients) so that
// shared CI machines pass, while a regression of an order of magnitude does
// not. It runs when HTTPMON_PERF=1 (the CI perf job).
func TestPerfBudget(t *testing.T) {
	if os.Getenv("HTTPMON_PERF") != "1" {
		t.Skip("set HTTPMON_PERF=1 to run the performance budget")
	}
	const (
		maxAddedMedian = 3 * time.Millisecond
		minRate        = 1500.0 // requests per second at 20 clients
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"items":[1,2,3]}`) //nolint:errcheck
	}))
	defer upstream.Close()
	useStats(t, "")
	useSummary(t)
	saved := swapTextOut(io.Discard)
	defer swapTextOut(saved)

	proxy := httptest.NewServer(http.HandlerFunc(handleHTTP))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	direct := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	via := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), MaxIdleConnsPerHost: 64}}

	median := func(c *http.Client, n int) time.Duration {
		d := make([]time.Duration, n)
		for i := range d {
			start := time.Now()
			resp, err := c.Get(upstream.URL + "/x")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
			d[i] = time.Since(start)
		}
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return d[n/2]
	}
	median(via, 50) // warm up
	added := median(via, 500) - median(direct, 500)
	t.Logf("added median latency: %v (budget %v)", added, maxAddedMedian)
	if added > maxAddedMedian {
		t.Errorf("httpmon adds %v to a request's median latency; budget %v", added, maxAddedMedian)
	}

	const clients, per = 20, 200
	var wg sync.WaitGroup
	start := time.Now()
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range per {
				resp, err := via.Get(upstream.URL + "/x")
				if err != nil {
					t.Error(err)
					return
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	rate := float64(clients*per) / time.Since(start).Seconds()
	t.Logf("throughput: %.0f requests/s at %d clients (budget %.0f)", rate, clients, minRate)
	if rate < minRate {
		t.Errorf("throughput %.0f requests/s; budget %.0f", rate, minRate)
	}
}

// TestPerfBudget_Session guards reading a large session: one exchange by id
// through the index, and HAR export streamed rather than held in memory.
func TestPerfBudget_Session(t *testing.T) {
	if os.Getenv("HTTPMON_PERF") != "1" {
		t.Skip("set HTTPMON_PERF=1 to run the performance budget")
	}
	const n = 20000
	dir := t.TempDir()
	w, err := store.OpenWriter(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 2000)
	for i := 1; i <= n; i++ {
		w.Write(&exchange.Exchange{V: exchange.Version, ID: i, Method: "GET", Kind: "http", //nolint:errcheck
			URL: fmt.Sprintf("https://api.example.com/item/%d", i), Status: 200,
			Response: &exchange.Message{Headers: exchange.Headers{}, Body: &body.Rendered{Size: 2000, Raw: body.NewRaw([]byte(pad), false)}}})
	}
	w.Close() //nolint:errcheck

	start := time.Now()
	out, code := runQuery(t, dir, "--id", strconv.Itoa(n-1), "--format", "json")
	took := time.Since(start)
	t.Logf("query --id on %d exchanges: %v", n, took)
	if code != 0 || !strings.Contains(out, fmt.Sprintf("/item/%d", n-1)) {
		t.Fatalf("query --id failed (exit %d)", code)
	}
	if took > 300*time.Millisecond {
		t.Errorf("query --id took %v; budget 300ms", took)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	done := make(chan struct{})
	var peak uint64
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
				runtime.ReadMemStats(&m)
				peak = max(peak, m.HeapInuse)
			}
		}
	}()
	if _, code := runQuery(t, dir, "--format", "har"); code != 0 {
		t.Fatalf("HAR export failed")
	}
	close(done)
	// Holding the session, as 4.0 did, peaked at about 8 times its size;
	// streaming stays well under half that (the figure includes garbage
	// not yet collected).
	fi, _ := os.Stat(filepath.Join(dir, store.Current))
	grew := int64(peak) - int64(before.HeapInuse)
	t.Logf("HAR export of %d exchanges (%d MB session): heap grew %d MB", n, fi.Size()>>20, grew>>20)
	if grew > 4*fi.Size() {
		t.Errorf("HAR export grew the heap by %d MB; budget 4× the session, %d MB", grew>>20, 4*fi.Size()>>20)
	}
}
