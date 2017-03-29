package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidLogLine(t *testing.T) {
	_, err := findMatches("Jan 1 15:39:43 badlog haproxy[9000]")
	if err == nil {
		t.Errorf("Expected an error when processing an invalid log line, got none")
	}
}

func TestHAProxyLogFromMap(t *testing.T) {
	line := `Jan 1 15:39:43 localhost haproxy[9000]: 127.0.0.1:59060 [01/Jan/2017:15:39:43.494] test-frontend test-backends/127.0.0.2 0/0/1/3/4 200 1910 - - ---- 10/0/0/0/0 1/2 {RQ123} "POST /v1/test_route HTTP/1.1"`
	matches, err := findMatches(line)
	if err != nil {
		t.Fatalf("Unexpected error matching the line %v (%v)", err, matches)
	}
	if len(matches) < 1 {
		t.Fatalf("Got 0 matches")
	}
	log, errs := newHaproxyLogFromMap(matches)
	if err != nil {
		t.Fatalf("%v %v", log, errs)
	}
	assert.Equal(t, 9000, log.PID)
	assert.Equal(t, "haproxy", log.ProcessName)
	assert.Equal(t, "127.0.0.1", log.ClientIP)
	assert.Equal(t, "59060", log.ClientPort)
	assert.Equal(t, "test-frontend", log.FrontendName)
	assert.Equal(t, "test-backends", log.BackendName)
	assert.Equal(t, "127.0.0.2", log.ServerName)
	assert.Equal(t, 0, log.Tw)
	assert.Equal(t, 0, log.Tq)
	assert.Equal(t, 1, log.Tc)
	assert.Equal(t, 3, log.Tr)
	assert.Equal(t, 4, log.Tt)
	assert.Equal(t, "", log.CapturedResponseHeaders)
	assert.Equal(t, "-", log.CapturedRequestCookie)
	assert.Equal(t, "-", log.CapturedResponseCookie)
	assert.Equal(t, "----", log.TerminationState)
	assert.Equal(t, uint16(200), log.StatusCode)
	assert.Equal(t, 1910, log.BytesRead)
	assert.Equal(t, 10, log.Actconn)
	assert.Equal(t, 0, log.Feconn)
	assert.Equal(t, 0, log.Beconn)
	assert.Equal(t, 0, log.Srvconn)
	assert.Equal(t, 0, log.Retries)
	assert.Equal(t, 1, log.SrvQueue)
	assert.Equal(t, 2, log.BackendQueue)
	assert.Equal(t, "RQ123", log.CapturedRequestHeaders)
	assert.Equal(t, "POST /v1/test_route HTTP/1.1", log.Request)
}
