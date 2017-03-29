package lib

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/opentracing/opentracing-go"
	ot_log "github.com/opentracing/opentracing-go/log"
)

var (
	HAProxyTimestamp    = "02/Jan/2006:15:04:05.999"
	defaultHaproxyRegex = regexp.MustCompile(`^(?P<syslog_time>[^ ]* +[^ ]* +[^ ]*) (?P<syslog_host>[\w\-\.]+) (?P<ps>\w+)\[(?P<pid>\d+)\]: ((?P<c_ip>[\w\.]+):(?P<c_port>\d+) \[(?P<timestamp>.+)\] (?P<f_end>[\w\~\-]+) (?P<b_end>[\w\-]+)\/(?P<b_server>[\w\.\-]+) (?P<tq>\-?\d+)\/(?P<tw>\-?\d+)\/(?P<tc>\-?\d+)\/(?P<tr>\-?\d+)\/\+?(?P<tt>\d+) (?P<status_code>\d+) \+?(?P<bytes>\d+) (?P<req_cookie>\S?) (?P<res_cookie>\S?) (?P<t_state>[\w\-]+) (?P<actconn>\d+)\/(?P<feconn>\d+)\/(?P<beconn>\d+)\/(?P<srv_conn>\d+)\/\+?(?P<retries>\d+) (?P<srv_queue>\d+)\/(?P<backend_queue>\d+) (\{(?P<req_headers>[^}]*)\} )?(\{?(?P<res_headers>[^}]*)\}? )?"(?P<request>[^"]*)"?)`)

	ErrNoMatch = fmt.Errorf("Could not match line with regex")
)

type multiError []error

func (m multiError) Error() string {
	errors := make([]string, len(m))
	for i, err := range m {
		errors[i] = fmt.Sprintf("- %s", err)
	}
	return strings.Join(errors, "/n")
}

// HAProxyHTTPLog represents a parsed HAProxy log line.
// A more in detail description of the fields can be found here:
// https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt#L14991
type HAProxyHTTPLog struct {
	Request     string
	ProcessName string
	PID         int
	// Client IP is the IP address of the client which initiated the TCP
	// connection to haproxy.
	ClientIP   string
	ClientPort string
	// StartTime is the exact time when the TCP connection was received by HAProxy
	StartTime time.Time
	Retries   int
	// StatusCode is the HTTP status code returned to the client.
	StatusCode uint16
	// FrontendName is the name of the frontend that received and processed the
	// request.
	FrontendName string
	// BackendName is the name of the backend that was selected to managed the connection
	// to the server.
	BackendName string
	// ServerName is the name of the last server to which the connection
	// was sent.
	ServerName string
	// BytesRead is the total number of bytes transmitted to the client.
	BytesRead int
	// Tr is the total time in milliseconds spent waiting for a full HTTP request
	// from the client (not counting body) after the first byte was received.
	Tr int
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
	// TerminationState is the condition the session was in when the session ended
	TerminationState       string
	CapturedRequestCookie  string
	CapturedResponseCookie string
	// Actconn is the number of concurrent connections on the process at the time
	// the session was logged.
	Actconn int
	// Feconn is the number of concurrent connections on the front end when the
	// session was logged.
	Feconn int
	// Beconn is the nuber of concurrent connections handled by the backend when
	// the session was logged.
	Beconn int
	// Srv is the number of concurrent connections still active on the server
	// when the session was logged.
	Srvconn int
	// SrvQueue is the total number of requests which were processed before
	// this one in the server queue.
	SrvQueue int
	// BackendQueue is the total number of requests which were processed before
	// this one in the backend's global queue.
	BackendQueue            int
	CapturedRequestHeaders  string
	CapturedResponseHeaders string
}

// ProcessLine looks at a given line and creates a span with start and end
// times based on the durations and log timestamp.
// It returns an error if there was an issue parsing or creating the span.
func (p Processor) ProcessLine(line string) error {
	matches, err := findMatches(line)
	if err != nil {
		return err
	}
	logInfo, err := newHaproxyLogFromMap(matches)
	if err != nil {
		return err
	}
	return p.createSpans(logInfo)
}

func findMatches(line string) (map[string]string, error) {
	match := defaultHaproxyRegex.FindStringSubmatch(line)
	if match == nil {
		return nil, ErrNoMatch
	}
	matches := make(map[string]string, defaultHaproxyRegex.NumSubexp())
	for i, name := range defaultHaproxyRegex.SubexpNames() {
		matches[name] = match[i]
	}
	return matches, nil
}

func newHaproxyLogFromMap(matches map[string]string) (HAProxyHTTPLog, error) {
	var errors multiError
	logInfo := HAProxyHTTPLog{}
	for name, val := range matches {
		switch name {
		case "ps":
			logInfo.ProcessName = val
		case "pid":
			if pid, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.PID = pid
			}
		case "c_ip":
			logInfo.ClientIP = val
		case "c_port":
			logInfo.ClientPort = val
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
			logInfo.ServerName = val
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
				logInfo.Tr = tr
			}
		case "tq":
			if tq, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Tq = tq
			}
		case "t_state":
			logInfo.TerminationState = val
		case "actconn":
			if actconn, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Actconn = actconn
			}
		case "beconn":
			if beconn, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Beconn = beconn
			}
		case "feconn":
			if feconn, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Feconn = feconn
			}
		case "srv_conn":
			if srvconn, err := strconv.Atoi(val); err != nil {
				errors = append(errors, err)
			} else {
				logInfo.Srvconn = srvconn
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
		case "res_headers":
			logInfo.CapturedResponseHeaders = val
		case "req_cookie":
			logInfo.CapturedRequestCookie = val
		case "res_cookie":
			logInfo.CapturedResponseCookie = val
		case "tc":
			if tc, err := strconv.Atoi(val); err != nil {
				errors = append(errors, fmt.Errorf("Could not parse tc %v (%v)", val, err))
			} else {
				logInfo.Tc = tc
			}
		case "retries":
			if retries, err := strconv.Atoi(val); err != nil {
				errors = append(errors, fmt.Errorf("Could not parse retries %v (%v)", val, err))
			} else {
				logInfo.Retries = retries
			}
		}
	}
	return logInfo, errors
}

func (p Processor) createSpans(log HAProxyHTTPLog) error {
	var (
		requestError    bool
		queueError      bool
		serverError     bool
		clientError     bool
		connectionError bool
	)
	if log.StartTime.IsZero() {
		return fmt.Errorf("Log contains a zero time value")
	}

	if log.Tw == -1 {
		queueError = true
		requestError = true
	}

	if log.Tr == -1 {
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

	topSpan := p.tracer.StartSpan(
		"haproxy_request:"+log.BackendName,
		opentracing.StartTime(log.StartTime))

	if err := p.parentSpanCallback(topSpan, log); err != nil {
		return err
	}

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
		clientSpan := p.tracer.StartSpan(
			"client_read:"+log.BackendName,
			opentracing.StartTime(clientTimeStart),
			opentracing.ChildOf(topSpan.Context()))
		if queueError != true {
			queueTimeStart := clientTimeEnd
			queueTimeEnd := queueTimeStart.Add(time.Duration(log.Tw) * time.Millisecond)
			queueSpan := p.tracer.StartSpan(
				"queue_wait:"+log.BackendName,
				opentracing.StartTime(queueTimeStart),
				opentracing.FollowsFrom(clientSpan.Context()))
			if connectionError != true {
				connectionTimeStart := queueTimeEnd
				connectionTimeEnd := connectionTimeStart.Add(time.Duration(log.Tc) * time.Millisecond)
				connectionSpan := p.tracer.StartSpan(
					"connection:"+log.BackendName,
					opentracing.StartTime(connectionTimeStart),
					opentracing.FollowsFrom(queueSpan.Context()))
				if serverError != true {
					responseTimeStart := connectionTimeEnd
					headerTime := responseTimeStart.Add(time.Duration(log.Tr) * time.Millisecond)
					responseTimeEnd := endTime
					serverSpan := p.tracer.StartSpan(
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
										ot_log.Int("header_millis", log.Tr)}}}})
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
func ParseStatusClass(code uint16) (class string) {
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
