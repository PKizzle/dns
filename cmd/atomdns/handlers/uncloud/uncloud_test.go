package uncloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/uncloud/model"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestUncloud(t *testing.T) {
	u := new(Uncloud)
	co := dnsserver.NewTestController(`
    uncloud testdata/uncld.db {
        addr :0
    }
`)
	err := u.Setup(co)
	if err != nil {
		t.Fatal(err)
	}
	u.Name = "example.org."
	co.Global.Startup()

	defer u.Listener.Close()
	defer func() {
		u.db.Exec("DELETE FROM rrs")
	}()

	_, port, _ := net.SplitHostPort(u.Listener.Addr().String())
	endpoint := fmt.Sprintf("http://localhost:%s/v1", port)

	domain, token, err := ReserveDomain(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if token != defaultToken {
		t.Errorf("expected %s, got %s", defaultToken, token)
	}

	records := []model.RecordRequest{
		{Name: "app", Type: "A", Values: []string{"127.0.0.1"}},
	}
	resp, err := CreateRecords(endpoint, domain, token, records)
	if err != nil {
		t.Fatal(err)
	}
	if resp[0].FQDN != "app."+domain {
		t.Fatalf("expected %s, got %s", "app."+domain, resp[0].FQDN)
	}
}

// this is the actual implementation in uncloud to register domains and records.

func ReserveDomain(endpoint string) (string, string, error) {
	url := fmt.Sprintf("%s/%s", endpoint, "domains")
	req, err := request(http.MethodPost, url, nil, "")
	if err != nil {
		return "", "", err
	}

	resp := &model.DomainResponse{}
	err = do(req, resp)
	if err != nil {
		return "", "", err
	}

	return resp.Name, resp.Token, nil
}

func CreateRecords(endpoint, domain, token string, records []model.RecordRequest) ([]model.RecordResponse, error) {
	url := fmt.Sprintf("%s/domains/%s/records", endpoint, domain)

	var resp []model.RecordResponse
	for _, recordRequest := range records {
		body, err := jsonBody(recordRequest)
		if err != nil {
			return resp, err
		}

		req, err := request(http.MethodPost, url, body, token)
		if err != nil {
			return resp, err
		}

		var recordResp model.RecordResponse
		if err = do(req, &recordResp); err != nil {
			return resp, err
		}
		resp = append(resp, recordResp)
	}

	return resp, nil
}

func request(method string, url string, body io.Reader, token string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	if token != "" {
		bearer := "Bearer " + token
		req.Header.Add("Authorization", bearer)
	}

	return req, nil
}

func do(req *http.Request, responseBody any) error {
	c := http.DefaultClient
	c.Timeout = 5 * time.Second

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		var authError AuthErrorResponse

		err = json.Unmarshal(body, &authError)
		if err != nil {
			return fmt.Errorf("unmarshal auth error response: %w", err)
		}

		if authError.Data.NoDomain {
			return errors.New("the supplied domain failed authentication")
		}

		return errors.New("authentication failed")
	}

	if code := resp.StatusCode; code < 200 || code > 300 {
		return fmt.Errorf("unexpected response status code: %d", code)
	}

	if responseBody != nil {
		err = json.Unmarshal(body, responseBody)
		if err != nil {
			return fmt.Errorf("unmarshal response body (%s): %w", string(body), err)
		}
	}

	return nil
}

func jsonBody(payload any) (io.Reader, error) {
	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(payload)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

type AuthErrorResponse struct {
	Status  int           `json:"status,omitempty"`
	Message string        `json:"msg,omitempty"`
	Data    authErrorData `json:"data"`
}

type authErrorData struct {
	NoDomain bool `json:"noDomain"`
}
