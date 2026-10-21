/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	C "github.com/pmkol/mosdns-x/pkg/query_context"
	H "github.com/pmkol/mosdns-x/pkg/server/http_handler"
	"github.com/pmkol/mosdns-x/pkg/upstream"
)

type protocolRecorder struct {
	mu       sync.Mutex
	protocol string
}

func (h *protocolRecorder) ServeDNS(_ context.Context, req *dns.Msg, meta *C.RequestMeta) (*dns.Msg, error) {
	h.mu.Lock()
	h.protocol = meta.GetProtocol()
	h.mu.Unlock()
	r := new(dns.Msg)
	r.SetReply(req)
	return r, nil
}

// DoH over eTLS must negotiate h2 between our server and our upstream.
func TestServeHTTP_eTLS_H2(t *testing.T) {
	rec := new(protocolRecorder)
	hh, err := H.NewHandler(H.HandlerOpts{DNSHandler: rec})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(ServerOpts{
		HttpHandler: hh,
		Cert:        "testdata/test.test.cert",
		Key:         "testdata/test.test.key",
	})
	defer s.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl, err := s.CreateETLSListner(l, []string{"h2"})
	if err != nil {
		t.Fatal(err)
	}
	go s.ServeHTTP(tl)

	u, err := upstream.NewUpstream("https://"+l.Addr().String()+"/dns-query", &upstream.Opt{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := u.ExchangeContext(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode %s", dns.RcodeToString[r.Rcode])
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.protocol != C.ProtocolH2 {
		t.Fatalf("server saw protocol %q, want %q", rec.protocol, C.ProtocolH2)
	}
}
