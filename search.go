package ssdp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/alexballas/go-ssdp/internal/multicast"
	"github.com/alexballas/go-ssdp/internal/ssdplog"
)

// Service is discovered service.
type Service struct {
	// Type is a property of "ST"
	Type string

	// USN is a property of "USN"
	USN string

	// Location is a property of "LOCATION"
	Location string

	// Server is a property of "SERVER"
	Server string

	// From is the sender (UDP source address) of the response.
	From net.Addr

	rawHeader http.Header
	maxAge    *int
}

var rxMaxAge = regexp.MustCompile(`\bmax-age\s*=\s*(\d+)\b`)

func extractMaxAge(s string, value int) int {
	v := value
	if m := rxMaxAge.FindStringSubmatch(s); m != nil {
		i64, err := strconv.ParseInt(m[1], 10, 32)
		if err == nil {
			v = int(i64)
		}
	}
	return v
}

// MaxAge extracts "max-age" value from "CACHE-CONTROL" property.
func (s *Service) MaxAge() int {
	if s.maxAge == nil {
		s.maxAge = new(int)
		*s.maxAge = extractMaxAge(s.rawHeader.Get("CACHE-CONTROL"), -1)
	}
	return *s.maxAge
}

// Header returns all properties in response of search.
func (s *Service) Header() http.Header {
	return s.rawHeader
}

const (
	// All is a search type to search all services and devices.
	All = "ssdp:all"

	// RootDevice is a search type to search UPnP root devices.
	RootDevice = "upnp:rootdevice"
)

// Search searches services by SSDP.
func Search(searchType string, waitSec int, localAddr string) ([]Service, error) {
	// dial multicast UDP packet.
	conn, err := multicast.Listen(&multicast.AddrResolver{Addr: localAddr})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ssdplog.Printf("search on %s", conn.LocalAddr().String())

	// send request.
	addr, err := multicast.SendAddr()
	if err != nil {
		return nil, err
	}
	msg, err := buildSearch(addr, searchType, waitSec)
	if err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo(multicast.BytesDataProvider(msg), addr); err != nil {
		return nil, err
	}

	// wait response.
	var c searchCollector
	d := time.Second * time.Duration(waitSec)
	if err := conn.ReadPackets(d, c.handle); err != nil {
		return nil, err
	}
	if c.dropped > 0 {
		ssdplog.Printf("search dropped %d responses over limits (%d total, %d per source)", c.dropped, maxSearchResponses, maxSearchResponsesPerSource)
	}

	return c.list, nil
}

const (
	// maxSearchResponseSize drops datagrams larger than any real SSDP
	// response, which fits in one MTU.
	maxSearchResponseSize = 8 << 10

	// maxSearchResponses bounds memory held during the wait window, so a
	// flood of responses cannot grow the list without limit.
	maxSearchResponses = 4096

	// maxSearchResponsesPerSource keeps one sender from filling
	// maxSearchResponses before real devices, which answer after a random
	// delay of up to MX seconds, get a chance.
	maxSearchResponsesPerSource = 128
)

// searchCollector gathers search responses within size and count bounds.
// Responses past the bounds are dropped while reading continues, so the
// socket keeps draining until the wait window ends. Responses without a
// LOCATION and exact repeats (same source, LOCATION, ST and USN) are skipped
// before counting; distinct ST/USN records for one LOCATION are kept.
type searchCollector struct {
	list      []Service
	dropped   int
	seen      map[searchKey]struct{}
	perSource map[string]int
}

type searchKey struct {
	source, location, st, usn string
}

func (c *searchCollector) handle(a net.Addr, d []byte) error {
	if len(d) > maxSearchResponseSize {
		ssdplog.Printf("oversized search response from %s: %d bytes", a.String(), len(d))
		return nil
	}
	srv, err := parseService(a, d)
	if err != nil {
		ssdplog.Printf("invalid search response from %s: %s", a.String(), err)
		return nil
	}
	if srv.Location == "" {
		return nil
	}
	// Key on IP, not port: one host may answer from several ports. The
	// multicast readers pass a *net.UDPAddr; anything else keys as-is rather
	// than panicking.
	source := a.String()
	if ua, ok := a.(*net.UDPAddr); ok {
		source = ua.IP.String()
	}
	key := searchKey{source: source, location: srv.Location, st: srv.Type, usn: srv.USN}
	if _, dup := c.seen[key]; dup {
		return nil
	}
	if len(c.list) >= maxSearchResponses || c.perSource[source] >= maxSearchResponsesPerSource {
		c.dropped++
		return nil
	}
	if c.seen == nil {
		c.seen = make(map[searchKey]struct{})
		c.perSource = make(map[string]int)
	}
	c.seen[key] = struct{}{}
	c.perSource[source]++
	c.list = append(c.list, *srv)
	ssdplog.Printf("search response from %s: %s", a.String(), srv.USN)
	return nil
}

func buildSearch(raddr net.Addr, searchType string, waitSec int) ([]byte, error) {
	b := new(bytes.Buffer)
	// FIXME: error should be checked.
	b.WriteString("M-SEARCH * HTTP/1.1\r\n")
	fmt.Fprintf(b, "HOST: %s\r\n", raddr.String())
	fmt.Fprintf(b, "MAN: %q\r\n", "ssdp:discover")
	fmt.Fprintf(b, "MX: %d\r\n", waitSec)
	fmt.Fprintf(b, "ST: %s\r\n", searchType)
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

var (
	errWithoutHTTPPrefix = errors.New("without HTTP prefix")
)

var endOfHeader = []byte{'\r', '\n', '\r', '\n'}

func parseService(addr net.Addr, data []byte) (*Service, error) {
	if !bytes.HasPrefix(data, []byte("HTTP")) {
		return nil, errWithoutHTTPPrefix
	}
	// Complement newlines on tail of header for buggy SSDP responses.
	if !bytes.HasSuffix(data, endOfHeader) {
		// why we should't use append() for this purpose:
		// https://play.golang.org/p/IM1pONW9lqm
		data = bytes.Join([][]byte{data, endOfHeader}, nil)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return &Service{
		Type:      resp.Header.Get("ST"),
		USN:       resp.Header.Get("USN"),
		Location:  resp.Header.Get("LOCATION"),
		Server:    resp.Header.Get("SERVER"),
		From:      addr,
		rawHeader: resp.Header,
	}, nil
}
