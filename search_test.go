package ssdp

import (
	"net"
	"strings"
	"sync"
	"testing"
)

func testMaxAge(t *testing.T, s string, expect int) {
	act := extractMaxAge(s, -1)
	if act != expect {
		t.Errorf("max-age for %q should be %d but actually %d", s, expect, act)
	}
}

func TestExtractMaxAge(t *testing.T) {
	// empty
	testMaxAge(t, "", -1)
	// spaces around `=`
	testMaxAge(t, "max-age=100", 100)
	testMaxAge(t, "max-age = 200", 200)
	testMaxAge(t, "max-age= 300", 300)
	testMaxAge(t, "max-age =400", 400)
	// minus
	testMaxAge(t, "max-age=-100", -1)
	// invalid name
	testMaxAge(t, "foo=100", -1)
	// contained valid name
	testMaxAge(t, "foomax-age=100", -1)
	// surrounded
	testMaxAge(t, ";max-age=500;", 500)
	testMaxAge(t, ";max-age=600", 600)
	testMaxAge(t, "max-age=700;", 700)
}

func TestSearch_Request(t *testing.T) {
	searchType := "test:search+request"

	var mu sync.Mutex
	var mm []*SearchMessage
	m := newTestMonitor(searchType, nil, nil, func(m *SearchMessage) {
		mu.Lock()
		mm = append(mm, m)
		mu.Unlock()
	})
	err := m.Start()
	if err != nil {
		t.Fatalf("failed to start Monitor: %s", err)
	}
	defer m.Close()

	srvs, err := Search(searchType, 1, "")
	if err != nil {
		t.Fatalf("failed to Search: %s", err)
	}
	if len(srvs) > 0 {
		t.Errorf("unexpected services: %+v", srvs)
	}

	if len(mm) < 1 {
		t.Fatal("no search detected")
	}
	_, port, err := net.SplitHostPort(mm[0].From.String())
	if err != nil {
		t.Fatalf("failed to split host and port: %s", err)
	}
	port = ":" + port

	expHdr := map[string]string{
		"Man": `"ssdp:discover"`,
		"Mx":  "1",
		"St":  "test:search+request",
	}
	for i, m := range mm {
		if m.Type != "test:search+request" {
			t.Errorf("unmatch type#%d:\nwant=%q\n got=%q", i, "test:search+request", m.Type)
		}
		if strings.HasSuffix(port, m.From.String()) {
			t.Errorf("unmatch port#%d:\nwant=%q\n got=%q", i, port, m.From.String())
		}

		h := m.Header()
		for k := range h {
			exp, ok := expHdr[k]
			if !ok {
				t.Errorf("unexpected header #%d %q=%q", i, k, h.Get(k))
			} else if act := h.Get(k); act != exp {
				t.Errorf("header #%d %q value mismatch:\nwant=%q\n got=%q", i, k, exp, act)
			}
		}
	}
}

func TestSearch_Response(t *testing.T) {
	a, err := Advertise("test:search+response", "usn:search+response", "location:search+response", "server:search+response", 600)
	if err != nil {
		t.Fatalf("failed to Advertise: %s", err)
	}
	defer a.Close()

	srvs, err := Search("test:search+response", 1, "")
	if err != nil {
		t.Fatalf("failed to Search: %s", err)
	}
	if len(srvs) == 0 {
		t.Errorf("no services found")
	}

	//t.Logf("found %d services", len(srvs))
	for i, s := range srvs {
		if s.Type != "test:search+response" {
			t.Errorf("unexpected service#%d type: want=%q got=%q", i, "test:search+response", s.Type)
		}
		if s.USN != "usn:search+response" {
			t.Errorf("unexpected service#%d usn: want=%q got=%q", i, "usn:search+response", s.USN)
		}
		if s.Location != "location:search+response" {
			t.Errorf("unexpected service#%d location: want=%q got=%q", i, "location:search+response", s.Location)
		}
		if s.Server != "server:search+response" {
			t.Errorf("unexpected service#%d server: want=%q got=%q", i, "server:search+response", s.Server)
		}
		if ua, ok := s.From.(*net.UDPAddr); !ok || ua.IP == nil {
			t.Errorf("service#%d missing UDP source address: got=%v", i, s.From)
		}
	}
}

func TestSearchCollector(t *testing.T) {
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 1900}
	valid := []byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.1.20:8080/desc.xml\r\n\r\n")
	oversized := append(append([]byte{}, valid[:len(valid)-2]...),
		[]byte("X-PAD: "+strings.Repeat("a", maxSearchResponseSize)+"\r\n\r\n")...)

	tt := []struct {
		name        string
		packets     [][]byte
		wantKept    int
		wantDropped int
	}{
		{"oversized datagram ignored", [][]byte{oversized, valid}, 1, 0},
		{"count capped, rest drained", func() [][]byte {
			pp := make([][]byte, maxSearchResponses+3)
			for i := range pp {
				pp[i] = valid
			}
			return pp
		}(), maxSearchResponses, 3},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var c searchCollector
			for i, p := range tc.packets {
				if err := c.handle(from, p); err != nil {
					t.Fatalf("packet %d: handle stopped reading: %v", i, err)
				}
			}
			if len(c.list) != tc.wantKept || c.dropped != tc.wantDropped {
				t.Fatalf("kept=%d dropped=%d, want kept=%d dropped=%d", len(c.list), c.dropped, tc.wantKept, tc.wantDropped)
			}
			if got := c.list[0].From; got != net.Addr(from) {
				t.Fatalf("From = %v, want %v", got, from)
			}
		})
	}
}

func TestSearch_ServiceRawHeader(t *testing.T) {
	a, err := Advertise("test:search+servicerawheader", "usn:search+servicerawheader", "location:search+servicerawheader", "server:search+servicerawheader", 600)
	if err != nil {
		t.Fatalf("failed to Advertise: %s", err)
	}
	defer a.Close()

	srvs, err := Search("test:search+servicerawheader", 1, "")
	if err != nil {
		t.Fatalf("failed to Search: %s", err)
	}
	if len(srvs) == 0 {
		t.Fatal("no services found")
	}

	expHdr := map[string]string{
		"St":            "test:search+servicerawheader",
		"Usn":           "usn:search+servicerawheader",
		"Location":      "location:search+servicerawheader",
		"Server":        "server:search+servicerawheader",
		"Cache-Control": "max-age=600",
		"Ext":           "",
	}
	for i, s := range srvs {
		if s.Type != "test:search+servicerawheader" {
			t.Errorf("unmatch type#%d:\nwant=%q\n got=%q", i, "test:search+request", s.Type)
		}
		if s.USN != "usn:search+servicerawheader" {
			t.Errorf("unexpected alive#%d usn: want=%q got=%q", i, "usn:search+servicerawheader", s.USN)
		}
		if s.Location != "location:search+servicerawheader" {
			t.Errorf("unexpected alive#%d location: want=%q got=%q", i, "location:search+servicerawheader", s.Location)
		}
		if s.Server != "server:search+servicerawheader" {
			t.Errorf("unexpected alive#%d server: want=%q got=%q", i, "server:search+servicerawheader", s.Server)
		}
		if s.MaxAge() != 600 {
			t.Errorf("unexpected max-age: want=%d got=%d", 600, s.MaxAge())
		}

		h := s.Header()
		for k := range h {
			exp, ok := expHdr[k]
			if !ok {
				t.Errorf("unexpected header #%d %q=%q", i, k, h.Get(k))
			} else if act := h.Get(k); act != exp {
				t.Errorf("header #%d %q value mismatch:\nwant=%q\n got=%q", i, k, exp, act)
			}
		}
	}
}
