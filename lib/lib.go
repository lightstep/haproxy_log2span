package lib

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/lightstep/haproxy_log2span/network"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/log"
	"github.com/stvp/rollbar"
)

// ProcessLine looks at a given line and creates a span with start and end times based on the durations and log timestamp.
// It returns a err if there was an issue parsing or creating the span.
func ProcessLine(line string, matchRegex *regexp.Regexp, datadogClient *statsd.Client) {
	match := matchRegex.FindStringSubmatch(line)
	if match != nil {
		var (
			status_code   int
			status_class  string
			request       string
			f_end         string
			b_end         string
			b_server      string
			bytes         int
			srv_queue     int
			backend_queue int
			tw            int
			tt            int
			tr            int
			tq            int
			startTime     time.Time
			req_headers   string
			tc            int
			retries       int

			requestError    bool
			queueError      bool
			serverError     bool
			clientError     bool
			connectionError bool

			err error
		)

		datadogClient.Count("log_matched", 1, nil, 1)

		for i, name := range matchRegex.SubexpNames() {
			switch name {
			case "status_code":
				status_code, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					status_code = -1
					status_class = "unknown"
				} else {
					if status_code < 200 {
						status_class = "1xx"
					} else if status_code < 300 {
						status_class = "2xx"
					} else if status_code < 400 {
						status_class = "3xx"
					} else if status_code < 500 {
						status_class = "4xx"
					} else if status_code < 600 {
						status_class = "5xx"
					} else {
						status_class = "unknown"
					}
				}
			case "request":
				request = match[i]
			case "f_end":
				f_end = match[i]
			case "b_end":
				b_end = match[i]
			case "b_server":
				b_server = match[i]
			case "bytes":
				bytes, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					bytes = -1
				}
			case "srv_queue":
				srv_queue, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					srv_queue = -1
				}
			case "backend_queue":
				backend_queue, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					backend_queue = -1
				}
			case "tw":
				tw, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					tw = -1
				}
			case "tt":
				tt, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					tt = -1
				}
			case "tr":
				tr, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					tr = -1
				}
			case "tq":
				tq, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					tq = -1
				}
			case "timestamp":
				//2006-01-02T15:04:05.999999999Z07:00
				haproxyTime := "02/Jan/2006:15:04:05.999"
				startTime, err = time.Parse(haproxyTime, match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					datadogClient.Count("invalid_timestamp", 1, nil, 1)
					return
				}
				startTime = startTime.Add(time.Duration(8) * time.Hour)
			case "req_headers":
				if strings.HasPrefix(match[i], "RQ") {
					req_headers = match[i]

				} else {
					datadogClient.Count("headers_not_request_sid", 1, nil, 1)
					return
				}
			case "tc":
				tc, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					tc = -1
				}
			case "retries":
				retries, err = strconv.Atoi(match[i])
				if err != nil {
					rollbar.Error(rollbar.ERR, err)
					retries = -1
				}
			}
		}

		if tw == -1 {
			queueError = true
			requestError = true
			datadogClient.Count("set_queue_error", 1, nil, 1)
		}

		if tr == -1 {
			serverError = true
			requestError = true
			datadogClient.Count("set_server_error", 1, nil, 1)
		}

		if tq == -1 {
			clientError = true
			requestError = true
			datadogClient.Count("set_client_error", 1, nil, 1)
		}

		if tc == -1 {
			connectionError = true
			requestError = true
			datadogClient.Count("set_connection_error", 1, nil, 1)
		}

		endTime := startTime.Add(time.Duration(tt) * time.Millisecond)

		topSpan := opentracing.StartSpan(
			"haproxy_request:"+b_end,
			opentracing.StartTime(startTime))

		topSpan.SetTag("http.status_code", status_code)
		topSpan.SetTag("http.status_class", status_class)
		// This needs to be filtered before it can be included.
		// topSpan.SetTag("request", request)
		_ = request
		topSpan.SetTag("f_end", f_end)
		topSpan.SetTag("b_end", b_end)
		topSpan.SetTag("peer.ipv4", b_server)
		topSpan.SetTag("peer.zone", network.GetZone(b_server))
		topSpan.SetTag("bytes", bytes)
		topSpan.SetTag("srv_queue", srv_queue)
		topSpan.SetTag("backend_queue", backend_queue)
		topSpan.SetTag("guid:request_sid", req_headers)
		topSpan.SetTag("retries", retries)

		if status_code >= 500 {
			topSpan.SetTag("error", "true")
		}

		if requestError == true {
			topSpan.SetTag("requestError", requestError)
			topSpan.SetTag("queueError", queueError)
			topSpan.SetTag("serverError", serverError)
			topSpan.SetTag("requestError", requestError)
			topSpan.SetTag("connectionError", connectionError)
		}

		if clientError != true {
			clientTimeStart := startTime
			clientTimeEnd := clientTimeStart.Add(time.Duration(tq) * time.Millisecond)
			clientSpan := opentracing.StartSpan(
				"client_read:"+b_end,
				opentracing.StartTime(clientTimeStart),
				opentracing.ChildOf(topSpan.Context()))

			if queueError != true {
				queueTimeStart := clientTimeEnd
				queueTimeEnd := queueTimeStart.Add(time.Duration(tw) * time.Millisecond)
				queueSpan := opentracing.StartSpan(
					"queue_wait:"+b_end,
					opentracing.StartTime(queueTimeStart),
					opentracing.FollowsFrom(clientSpan.Context()))
				if connectionError != true {
					connectionTimeStart := queueTimeEnd
					connectionTimeEnd := connectionTimeStart.Add(time.Duration(tc) * time.Millisecond)
					connectionSpan := opentracing.StartSpan(
						"connection:"+b_end,
						opentracing.StartTime(connectionTimeStart),
						opentracing.FollowsFrom(queueSpan.Context()))
					if serverError != true {
						responseTimeStart := connectionTimeEnd
						headerTime := responseTimeStart.Add(time.Duration(tr) * time.Millisecond)
						responseTimeEnd := endTime
						serverSpan := opentracing.StartSpan(
							"response:"+b_end,
							opentracing.StartTime(responseTimeStart),
							opentracing.FollowsFrom(connectionSpan.Context()))
						serverSpan.FinishWithOptions(
							opentracing.FinishOptions{
								FinishTime: responseTimeEnd,
								LogRecords: []opentracing.LogRecord{
									opentracing.LogRecord{
										Timestamp: headerTime,
										Fields: []log.Field{
											log.Int("header_millis", tr)}}}})
					}
					connectionSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: connectionTimeEnd})
				}
				queueSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: queueTimeEnd})
			}
			clientSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: clientTimeEnd})
		}
		topSpan.FinishWithOptions(opentracing.FinishOptions{FinishTime: endTime})
	} else {
		datadogClient.Count("log_not_matched", 1, nil, 1)
	}

	return
}
