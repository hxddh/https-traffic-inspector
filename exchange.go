package main

import "sync"

// capturedRequest and capturedResponse are the two halves of an exchange as
// --record and --har need them, each available once its body has finished.
type capturedRequest struct {
	facts requestFacts
	body  bodyView
}

type capturedResponse struct {
	facts responseFacts
	body  bodyView
}

// exchangeJoiner pairs the two halves of each exchange by request ID.
//
// Either half may finish first. A server can answer before it has read the
// whole upload -- a 413, an auth failure, a bidirectional stream -- so the
// response body can end while the request body is still streaming. Assuming
// the request always came first silently dropped such exchanges.
type exchangeJoiner struct {
	mu    sync.Mutex
	reqs  map[int]capturedRequest
	resps map[int]capturedResponse
	// dropped holds IDs abandoned before their request half arrived, so that
	// a late arrival is discarded rather than parked forever.
	dropped map[int]struct{}
}

func newExchangeJoiner() *exchangeJoiner {
	return &exchangeJoiner{
		reqs:    make(map[int]capturedRequest),
		resps:   make(map[int]capturedResponse),
		dropped: make(map[int]struct{}),
	}
}

// captures joins exchanges for --record and --har.
var captures = newExchangeJoiner()

func (j *exchangeJoiner) addRequest(id int, r capturedRequest) {
	j.mu.Lock()
	if _, ok := j.dropped[id]; ok {
		delete(j.dropped, id)
		j.mu.Unlock()
		return
	}
	rs, ok := j.resps[id]
	if !ok {
		j.reqs[id] = r
		j.mu.Unlock()
		return
	}
	delete(j.resps, id)
	j.mu.Unlock()
	completeExchange(id, r, rs)
}

func (j *exchangeJoiner) addResponse(id int, rs capturedResponse) {
	j.mu.Lock()
	r, ok := j.reqs[id]
	if !ok {
		j.resps[id] = rs
		j.mu.Unlock()
		return
	}
	delete(j.reqs, id)
	j.mu.Unlock()
	completeExchange(id, r, rs)
}

// drop abandons an exchange that will never complete, such as one whose
// upstream request failed. The request half may still be in flight -- the
// transport closes the body after the failure is reported -- so its arrival
// is remembered and discarded.
func (j *exchangeJoiner) drop(id int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, hadReq := j.reqs[id]
	delete(j.reqs, id)
	delete(j.resps, id)
	if !hadReq {
		j.dropped[id] = struct{}{}
	}
}

// pending reports how many halves are waiting for a partner.
func (j *exchangeJoiner) pending() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.reqs) + len(j.resps) + len(j.dropped)
}

// completeExchange hands a finished exchange to each capture that wants it.
func completeExchange(id int, r capturedRequest, rs capturedResponse) {
	if recordMode {
		writeRecord(id, r, rs)
	}
	if harMode {
		addHAREntry(r, rs)
	}
}
