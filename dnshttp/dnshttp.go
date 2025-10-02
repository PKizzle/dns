// Package dnshttp deals with converting HTTP requests and responses to dns.Msg types. This is part of DNS
// over HTTP (DOH).
package dnshttp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"codeberg.org/miekg/dns"
)

// Request/Response from http pacg

// MimeType is the DOH mimetype.
const MimeType = "application/dns-message"

// Path is the URL path that is used by DOH.
const Path = "/dns-query"

// NewRequest returns a new DOH request given a HTTP method, URL and a [dns.Msg].
//
// The URL should not have a path, so exclude /dns-query. The URL will be prefixed with https:// by default,
// unless it's already prefixed with either http:// or https://. Supported methods are GET or POST.
func NewRequest(method, url string, m *dns.Msg) (*http.Request, error) {
	// TODO(miek): hijack buffer?
	if err := m.Pack(); err != nil {
		return nil, err
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	switch method {
	case http.MethodGet:
		b64 := base64.RawURLEncoding.EncodeToString(m.Data)
		req, err := http.NewRequest(method, url+Path+"?dns="+b64, nil)
		if err != nil {
			return req, err
		}
		req.Header.Set("Content-Type", MimeType)
		req.Header.Set("Accept", MimeType)
		return req, nil
	case http.MethodPost:
		req, err := http.NewRequest(method, url+Path, bytes.NewReader(m.Data))
		if err != nil {
			return req, err
		}
		req.Header.Set("Content-Type", MimeType)
		req.Header.Set("Accept", MimeType)
		return req, nil
	}
	return nil, fmt.Errorf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), method)
}

// Request converts req to a [dns.Msg].
func Request(req *http.Request) (*dns.Msg, error) {
	switch req.Method {
	case http.MethodGet:
		values := req.URL.Query()
		b64, ok := values["dns"]
		if !ok || len(b64) != 1 {
			return nil, fmt.Errorf("no 'dns' or multiple query parameter found")
		}
		buf, err := base64.RawURLEncoding.DecodeString(b64[0])
		if err != nil {
			return nil, err
		}
		m := &dns.Msg{Data: buf}
		err = m.Unpack()
		if err != nil {
			return m, err
		}
		return m, nil

	case http.MethodPost:
		defer req.Body.Close()
		m, err := msg(req.Body)
		if err != nil {
			return m, err
		}
		// MsgAcceptFunc
		return m, nil

	}
	return nil, fmt.Errorf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), req.Method)
}

// Response converts resp to a [dns.Msg].
func Response(resp *http.Response) (*dns.Msg, error) {
	defer resp.Body.Close()
	return msg(resp.Body)
}

// msg converts the (usually the body) ReadCloser to a [dns.Msg].
func msg(r io.ReadCloser) (*dns.Msg, error) {
	buf, err := io.ReadAll(http.MaxBytesReader(nil, r, 65536))
	if err != nil {
		return nil, err
	}
	m := &dns.Msg{Data: buf}
	err = m.Unpack()
	return m, err
}

// MsgAcceptAction is the function that checks if the incoming message is valid. It's a variable so it can be
// set at the beginning.
var MsgAcceptAction = DefaultMsgAcceptFunc

// DefaultMsgAcceptFunc checks if m has a message ID of zero. It also implements the check mandated by DOQ, that
// the Pseudo section cannot contain an TCP-KEEPALIVE option.
// See RFC 9250 and RFC 8484.
func DefaultMsgAcceptFunc(m *dns.Msg) dns.MsgAcceptAction {
	if m.ID != 0 {
		return dns.MsgReject
	}
	for _, o := range m.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			return dns.MsgReject
		}
	}
	return dns.MsgAccept
}
