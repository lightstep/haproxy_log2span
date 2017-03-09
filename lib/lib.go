package lib

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lightstep/haproxy_log2span/network"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	ot_log "github.com/opentracing/opentracing-go/log"
)

var (
	HAProxyTimestamp    = "02/Jan/2006:15:04:05.999"
	defaultHaproxyRegex = regexp.MustCompile(`^(?P<syslog_time>[^ ]* +[^ ]* +[^ ]*) (?P<syslog_host>[\w\-\.]+) (?P<ps>\w+)\[(?P<pid>\d+)\]: ((?P<c_ip>[\w\.]+):(?P<c_port>\d+) \[(?P<timestamp>.+)\] (?P<f_end>[\w\~\-]+) (?P<b_end>[\w\-]+)\/(?P<b_server>[\w\.\-]+) (?P<tq>\-?\d+)\/(?P<tw>\-?\d+)\/(?P<tc>\-?\d+)\/(?P<tr>\-?\d+)\/\+?(?P<tt>\d+) (?P<status_code>\d+) \+?(?P<bytes>\d+) (?P<req_cookie>\S?) (?P<res_cookie>\S?) (?P<t_state>[\w\-]+) (?P<actconn>\d+)\/(?P<feconn>\d+)\/(?P<beconn>\d+)\/(?P<srv_conn>\d+)\/\+?(?P<retries>\d+) (?P<srv_queue>\d+)\/(?P<backend_queue>\d+) (\{(?P<req_headers>[^}]*)\} )?(\{?(?P<res_headers>[^}]*)\}? )?"(?P<request>[^"]*)"?)`)
)

// HAProxyHTTPLog represents a parsed HAProxy log line.
// A more in detail description of the fields can be found here:
// https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt#L14991
type HAProxyHTTPLog struct {
	Request string
	Retries int
	// CapturedRequestHeaders contain any captured cookie headers.
	CapturedRequestHeaders string
	// StartTime is the exact time when the TCP connection was received by HAProxy
	StartTime time.Time
	// StatusCode is the HTTP status code returned to the client.
	StatusCode uint16
	// FrontendName is the name of the frontend that received and processed the
	// request.
	FrontendName string
	// BackendName is the name of the back that was selected to managed the connection
	// to the server.
	BackendName string
	// BackendServer is the name of the last server to which the connection
	// was sent.
	BackendServer string
	// BackendQueue is the total number of requests which were processed before
	// this one in the backend's global queue.
	BackendQueue int
	// SrvQueue is the total number of requests which were processed before
	// this one in the server queue.
	SrvQueue int
	// BytesRead is the total number of bytes transmitted to the client.
	BytesRead int
	// TR is the total time in milliseconds spent waiting for a full HTTP request
	// from the client (not counting body) after the first byte was received.
	TR int
	// Tw is the total time in milliseconds waiting in various queues.
	Tw int
	// Tc is the total time in milliseconds waiting for the server to send a full
	// HTTP response, not counting data.
	Tc int
	// Tt is the total time in milliseconds elapsesd between the accept and the
	// last close
	Tt int
	// Tq is the total time in milliseconds waiting for the client to send a full
	// HTTP request, not counting data.
	Tq int
}

// ProcessLine looks at a given line and creates a span with start and end times based on the durations and log timestamp.
// It returns an err if there was an issue parsing or creating the span.
func ProcessLine(line string) error {
	match := defaultHaproxyRegex.FindStringSubmatch(line)
	if match == nil {
		return fmt.Errorf("Could not match line with regex")
	}
	matches := make(map[string]string, defaultHaproxyRegex.NumSubexp())
	for i, name := range defaultHaproxyRegex.SubexpNames() {
		matches[name] = match[i]
	}
	logInfo, errs := newHaproxyLogFromMap(matches)
	if len(errs) != 0 {
		return fmt.Errorf("%v", errs)
	}
	return createSpans(logInfo)
}

func newHaproxyLogFromMap(matches map[string]string) (*HAProxyHTTPLog, []error) {
	var errors []error
	logInfo := &HAProxyHTTPLog{}
	for name, val := range matches {
		switch name {
		case "status_code":
			if statusCode, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.StatusCode = uint16(statusCode)
			}
		case "request":
			logInfo.Request = val
		case "f_end":
			logInfo.FrontendName = val
		case "b_end":
			logInfo.BackendName = val
		case "b_server":
			logInfo.BackendName = val
		case "bytes":
			if bytes, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.BytesRead = bytes
			}
		case "srv_queue":
			if srvQueue, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.SrvQueue = srvQueue
			}
		case "backend_queue":
			if backendQueue, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.BackendQueue = backendQueue
			}
		case "tw":
			if tw, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Tw = tw
			}
		case "tt":
			if tt, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Tt = tt
			}
		case "tr":
			if tr, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.TR = tr
			}
		case "tq":
			if tq, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Tq = tq
			}
		case "timestamp":
			if startTime, err := time.Parse(HAProxyTimestamp, val); err != nil {
				errors = append(errors, fmt.Errorf("Invalid timestamp %v (%v)", val, err))
			} else {
				// TODO: Remove hardcoded timezone correction
				logInfo.StartTime = startTime.Add(time.Duration(8) * time.Hour)
			}
		case "req_headers":
			logInfo.CapturedRequestHeaders = val
		case "tc":
			if tc, err := strconv.Atoi(val); err != nil {
				errors = append(errors, fmt.Errorf("Invalid timestamp %v (%v)", val, err))
			} else {
				logInfo.Tc = tc
			}
		case "retries":
			if retries, err := strconv.Atoi(val); err != nil {
				errors = append(errors, fmt.Errorf("Invalid timestamp %v (%v)", val, err))
			} else {
				logInfo.Retries = retries
			}
		}
	}
	return logInfo, errors
}

func addTagsToSpan(sp opentracing.Span, log HAProxyHTTPLog) error {
	statusClass := parseStatusClass(log.StatusCode)
	if !strings.HasPrefix(log.CapturedRequestHeaders, "RQ") {
		return fmt.Errorf("No SID provided")
	}
	if log.StatusCode >= 500 {
		ext.Error.Set(sp, true)
	}
	ext.HTTPStatusCode.Set(sp, log.StatusCode)
	sp.SetTag("http.status_class", statusClass)
	sp.SetTag("peer.zone", network.GetZone(log.BackendServer))
	sp.SetTag("peer.ipv4", log.BackendServer)
	sp.SetTag("retries", log.Retries)
	sp.SetTag("f_end", log.FrontendName)
	sp.SetTag("b_end", log.BackendName)
	sp.SetTag("bytes", log.BytesRead)
	sp.SetTag("srv_queue", log.SrvQueue)
	sp.SetTag("backend_queue", log.BackendQueue)
	// This needs to be filtered before it can be included.
	// topSpan.SetTag("request", log.request)
	// TODO: provide a callback that allows you to set certain tags like this
	sp.SetTag("guid:request_sid", log.CapturedRequestHeaders)
	return nil
}

func createSpans(log *HAProxyHTTPLog) error {
	var (
		requestError    bool
		queueError      bool
		serverError     bool
		clientError     bool
		connectionError bool
	)
	if log.StartTime.IsZero() {
		return fmt.Errorf("Log does not contain a time value")
	}

	if log.Tw == -1 {
		queueError = true
		requestError = true
	}

	if log.TR == -1 {
		serverError = true
		requestError = true
	}

	if log.Tq == -1 {
		clientError = true
		requestError = true
	}

	if log.Tc == -1 {
		connectionError = true
		requestError = true
	}

	endTime := log.StartTime.Add(time.Duration(log.Tt) * time.Millisecond)

	topSpan := opentracing.StartSpan(
		"haproxy_request:"+log.BackendName,
		opentracing.StartTime(log.StartTime))

	if requestError == true {
		topSpan.SetTag("requestError", requestError)
		topSpan.SetTag("queueError", queueError)
		topSpan.SetTag("serverError", serverError)
		topSpan.SetTag("requestError", requestError)
		topSpan.SetTag("connectionError", connectionError)
	}

	if clientError != true {
		clientTimeStart := log.StartTime
		clientTimeEnd := clientTimeStart.Add(time.Duration(log.Tq) * time.Millisecond)
		clientSpan := opentracing.StartSpan(
			"client_read:"+log.BackendName,
			opentracing.StartTime(clientTimeStart),
			opentracing.ChildOf(topSpan.Context()))

		if queueError != true {
			queueTimeStart := clientTimeEnd
			queueTimeEnd := queueTimeStart.Add(time.Duration(log.Tw) * time.Millisecond)
			queueSpan := opentracing.StartSpan(
				"queue_wait:"+log.BackendName,
				opentracing.StartTime(queueTimeStart),
				opentracing.FollowsFrom(clientSpan.Context()))
			if connectionError != true {
				connectionTimeStart := queueTimeEnd
				connectionTimeEnd := connectionTimeStart.Add(time.Duration(log.Tc) * time.Millisecond)
				connectionSpan := opentracing.StartSpan(
					"connection:"+log.BackendName,
					opentracing.StartTime(connectionTimeStart),
					opentracing.FollowsFrom(queueSpan.Context()))
				if serverError != true {
					responseTimeStart := connectionTimeEnd
					headerTime := responseTimeStart.Add(time.Duration(log.TR) * time.Millisecond)
					responseTimeEnd := endTime
					serverSpan := opentracing.StartSpan(
						"response:"+log.BackendName,
						opentracing.StartTime(responseTimeStart),
						opentracing.FollowsFrom(connectionSpan.Context()))
					serverSpan.FinishWithOptions(
						opentracing.FinishOptions{
							FinishTime: responseTimeEnd,
							LogRecords: []opentracing.LogRecord{
								opentracing.LogRecord{
									Timestamp: headerTime,
									Fields: []ot_log.Field{
										ot_log.Int("header_millis", log.TR)}}}})
				}
				connectionSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: connectionTimeEnd})
			}
			queueSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: queueTimeEnd})
		}
		clientSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: clientTimeEnd})
	}
	topSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: endTime})
	return nil
}

// parseStatusCode takes an HTTP response code, parses it to an int, and returns
// the code class it's in, e.g. 404 is a 4xx code.
func parseStatusClass(code uint16) (class string) {
	if code >= 100 && code < 200 {
		class = "1xx"
	} else if code < 300 {
		class = "2xx"
	} else if code < 400 {
		class = "3xx"
	} else if code < 500 {
		class = "4xx"
	} else if code < 600 {
		class = "5xx"
	} else {
		class = "unknown"
	}
	return class
}
