package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/hxddh/https-traffic-inspector/v5/internal/exchange"
)

// connIDs assigns a small monotonic id to each upstream socket (local->remote)
// so a session shows which exchanges shared a connection, without holding
// references to net.Conn.
var (
	connIDMu   sync.Mutex
	connIDMap  = map[string]int{}
	connIDNext int
)

func lookupConnID(local, remote string) int {
	if local == "" && remote == "" {
		return 0
	}
	key := local + "->" + remote
	connIDMu.Lock()
	defer connIDMu.Unlock()
	if id, ok := connIDMap[key]; ok {
		return id
	}
	if len(connIDMap) >= 4096 {
		clear(connIDMap)
	}
	connIDNext++
	connIDMap[key] = connIDNext
	return connIDNext
}

// upstreamTrace collects phase timings and connection metadata for one upstream request.
type upstreamTrace struct {
	mu sync.Mutex

	dnsStart   time.Time
	dnsDur     time.Duration
	tcpStart   time.Time
	tcpDur     time.Duration
	tlsStart   time.Time
	tlsDur     time.Duration
	gotConnAt  time.Time
	wroteReqAt time.Time
	firstByte  time.Time

	hasConn    bool
	reused     bool
	connID     int
	remoteAddr string
	tlsState   *tls.ConnectionState
}

func withUpstreamTrace(ctx context.Context) (context.Context, *upstreamTrace) {
	ut := &upstreamTrace{}
	ct := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			ut.mu.Lock()
			ut.dnsStart = time.Now()
			ut.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			ut.mu.Lock()
			if !ut.dnsStart.IsZero() {
				ut.dnsDur += time.Since(ut.dnsStart)
				ut.dnsStart = time.Time{}
			}
			ut.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			ut.mu.Lock()
			ut.tcpStart = time.Now()
			ut.mu.Unlock()
		},
		ConnectDone: func(_, _ string, _ error) {
			ut.mu.Lock()
			if !ut.tcpStart.IsZero() {
				ut.tcpDur += time.Since(ut.tcpStart)
				ut.tcpStart = time.Time{}
			}
			ut.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			ut.mu.Lock()
			ut.tlsStart = time.Now()
			ut.mu.Unlock()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			ut.mu.Lock()
			if !ut.tlsStart.IsZero() {
				ut.tlsDur += time.Since(ut.tlsStart)
				ut.tlsStart = time.Time{}
			}
			if err == nil {
				c := cs
				ut.tlsState = &c
			}
			ut.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			var local, remote string
			if info.Conn != nil {
				if info.Conn.LocalAddr() != nil {
					local = info.Conn.LocalAddr().String()
				}
				if info.Conn.RemoteAddr() != nil {
					remote = info.Conn.RemoteAddr().String()
				}
			}
			id := lookupConnID(local, remote)
			ut.mu.Lock()
			ut.hasConn = true
			ut.reused = info.Reused
			ut.connID = id
			ut.remoteAddr = remote
			ut.gotConnAt = time.Now()
			ut.mu.Unlock()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			ut.mu.Lock()
			ut.wroteReqAt = time.Now()
			ut.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			ut.mu.Lock()
			if ut.firstByte.IsZero() {
				ut.firstByte = time.Now()
			}
			ut.mu.Unlock()
		},
	}
	return httptrace.WithClientTrace(ctx, ct), ut
}

func (ut *upstreamTrace) finish(reqStart time.Time, headDur, totalDur time.Duration, respTLS *tls.ConnectionState) (*exchange.Timings, *exchange.ConnInfo) {
	recvDur := max(totalDur-headDur, 0)
	if ut == nil {
		return &exchange.Timings{
			WaitMs: millis(headDur),
			RecvMs: millis(recvDur),
		}, nil
	}
	ut.mu.Lock()
	defer ut.mu.Unlock()

	var sendDur time.Duration
	if !ut.gotConnAt.IsZero() && !ut.wroteReqAt.IsZero() && ut.wroteReqAt.After(ut.gotConnAt) {
		sendDur = ut.wroteReqAt.Sub(ut.gotConnAt)
	}
	waitDur := headDur - ut.dnsDur - ut.tcpDur - ut.tlsDur - sendDur
	if !ut.wroteReqAt.IsZero() && !ut.firstByte.IsZero() && ut.firstByte.After(ut.wroteReqAt) {
		waitDur = ut.firstByte.Sub(ut.wroteReqAt)
	}
	if waitDur < 0 {
		waitDur = 0
	}
	timings := &exchange.Timings{
		DNSMs:  millis(ut.dnsDur),
		TCPMs:  millis(ut.tcpDur),
		TLSMs:  millis(ut.tlsDur),
		SendMs: millis(sendDur),
		WaitMs: millis(waitDur),
		RecvMs: millis(recvDur),
	}

	cs := ut.tlsState
	if cs == nil {
		cs = respTLS
	}
	if !ut.hasConn && cs == nil {
		return timings, nil
	}
	ci := &exchange.ConnInfo{
		ID:         ut.connID,
		Reused:     ut.reused,
		RemoteAddr: ut.remoteAddr,
	}
	if cs != nil {
		ci.TLSVersion = tls.VersionName(cs.Version)
		ci.CipherSuite = tls.CipherSuiteName(cs.CipherSuite)
		ci.ALPN = cs.NegotiatedProtocol
		if len(cs.PeerCertificates) > 0 {
			fillCertInfo(ci, cs.PeerCertificates[0], reqStart)
		}
	}
	return timings, ci
}

func fillCertInfo(ci *exchange.ConnInfo, cert *x509.Certificate, now time.Time) {
	if cert == nil {
		return
	}
	subj := cert.Subject.CommonName
	if subj == "" && len(cert.DNSNames) > 0 {
		subj = cert.DNSNames[0]
	}
	ci.CertSubject = subj
	iss := cert.Issuer.CommonName
	if iss == "" && len(cert.Issuer.Organization) > 0 {
		iss = strings.Join(cert.Issuer.Organization, ", ")
	}
	ci.CertIssuer = iss
	if now.IsZero() {
		now = time.Now()
	}
	days := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
	ci.CertDaysLeft = &days
}
