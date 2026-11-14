package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
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
