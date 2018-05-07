//go:generate go run generate/protocol.go

package ga

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"io/ioutil"
	"crypto/tls"
	"time"
)

var trackingIDMatcher = regexp.MustCompile(`^UA-\d+-\d+$`)

func NewClient(trackingID string) (*Client, error) {
	if !trackingIDMatcher.MatchString(trackingID) {
		return nil, fmt.Errorf("invalid tracking id: %s", trackingID)
	}

	// Create default http client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // remove the checking tls
		DisableCompression: true, // Remove the compression (Accept-Encoding: gzip)
	}
	var httpClient = http.Client{
		Timeout:   time.Second * 30,
		Transport: transport,
	}

	return &Client{
		Debug:             	false,
		UseTLS:             true,
		HttpClient:         &httpClient,
		protocolVersion:    "1",
		protocolVersionSet: true,
		trackingID:         trackingID,
		clientID:           "go-ga",
		clientIDSet:        true,
	}, nil
}

type hitType interface {
	addFields(url.Values) error
}

func (c *Client) Send(h hitType) error {

	cpy := c.Copy()

	v := url.Values{}

	cpy.setType(h)

	err := cpy.addFields(v)
	if err != nil {
		return err
	}

	err = h.addFields(v)
	if err != nil {
		return err
	}

	urlStr := ""
	if cpy.Debug {
		urlStr = "https://www.google-analytics.com/debug/collect"
	} else if cpy.UseTLS {
		urlStr = "https://www.google-analytics.com/collect"
	} else {
		urlStr = "http://ssl.google-analytics.com/collect"
	}

	str := v.Encode()
	// Disable POST method
	//buf := bytes.NewBufferString(str)
	//resp, err := c.HttpClient.Post(url, "application/x-www-form-urlencoded", buf)

	// Use GET method
	urlStr = urlStr + "?" + str
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return err
	}
	// Set PHP User-Agent (Valid in GA by default)
	req.Header.Set("User-Agent", "THE ICONIC GA Measurement Protocol PHP Client (https://github.com/theiconic/php-ga-measurement-protocol)")
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("rejected by google with code %d", resp.StatusCode)
	}

	if cpy.Debug {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		fmt.Println(bodyString)
	}
	// fmt.Printf("POST %s => %d\n", str, resp.StatusCode)
	return nil
}
