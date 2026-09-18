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

package hosts

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
)

// 并发调用 LookupMsg 时，共享的 IP 列表不能被破坏：
// 每个应答都必须恰好包含配置里的全部 IP，且顺序需要被随机化。
func Test_hosts_ConcurrentLookupMsg(t *testing.T) {
	const hostsText = `
example.com 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.6 10.0.0.7 10.0.0.8 fd00::1 fd00::2 fd00::3 fd00::4 fd00::5 fd00::6 fd00::7 fd00::8
`
	m := domain.NewMixMatcher[*IPs]()
	m.SetDefaultMatcher(domain.MatcherDomain)
	if err := domain.LoadFromTextReader[*IPs](m, bytes.NewBuffer([]byte(hostsText)), ParseIPs); err != nil {
		t.Fatal(err)
	}
	h := NewHosts(m)

	wantV4, wantV6 := h.Lookup("example.com.")
	origV4 := append([]netip.Addr(nil), wantV4...)
	origV6 := append([]netip.Addr(nil), wantV6...)

	answerSet := func(r *dns.Msg) map[netip.Addr]int {
		got := make(map[netip.Addr]int)
		for _, rr := range r.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				ip, _ := netip.AddrFromSlice(rr.A)
				got[ip.Unmap()]++
			case *dns.AAAA:
				ip, _ := netip.AddrFromSlice(rr.AAAA)
				got[ip]++
			}
		}
		return got
	}
	check := func(t *testing.T, r *dns.Msg, want []netip.Addr) {
		t.Helper()
		if r == nil {
			t.Fatal("nil response")
		}
		got := answerSet(r)
		if len(r.Answer) != len(want) {
			t.Fatalf("answer count = %d, want %d", len(r.Answer), len(want))
		}
		for _, ip := range want {
			if n := got[ip]; n != 1 {
				t.Fatalf("ip %s appears %d times in answer, want exactly 1 (answer=%v)", ip, n, r.Answer)
			}
		}
	}

	const goroutines = 16
	const iterations = 2000
	var wg sync.WaitGroup
	errCh := make(chan string, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			typ := dns.TypeA
			want := origV4
			if g%2 == 1 {
				typ = dns.TypeAAAA
				want = origV6
			}
			q := new(dns.Msg)
			q.SetQuestion("example.com.", typ)
			for i := 0; i < iterations; i++ {
				r := h.LookupMsg(q)
				if r == nil {
					errCh <- "nil response"
					return
				}
				got := answerSet(r)
				for _, ip := range want {
					if got[ip] != 1 {
						errCh <- "ip " + ip.String() + " lost or duplicated in answer"
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Fatal(msg)
	}

	// 并发结束后，底层列表本身必须原封不动（顺序可以变，但元素集合不能变）。
	q4 := new(dns.Msg)
	q4.SetQuestion("example.com.", dns.TypeA)
	check(t, h.LookupMsg(q4), origV4)
	q6 := new(dns.Msg)
	q6.SetQuestion("example.com.", dns.TypeAAAA)
	check(t, h.LookupMsg(q6), origV6)

	// 顺序仍需随机化：多次查询不应总是同一顺序。
	first := h.LookupMsg(q4).Answer
	shuffled := false
	for i := 0; i < 64 && !shuffled; i++ {
		cur := h.LookupMsg(q4).Answer
		for j := range cur {
			if cur[j].(*dns.A).A.String() != first[j].(*dns.A).A.String() {
				shuffled = true
				break
			}
		}
	}
	if !shuffled {
		t.Fatal("answer order is never shuffled")
	}
}
