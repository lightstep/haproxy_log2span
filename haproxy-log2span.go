package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lightstep/haproxy_log2span/lib"
	"github.com/lightstep/haproxy_log2span/network"
	"github.com/lightstep/haproxy_log2span/platform"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/stvp/rollbar"

	"github.com/hpcloud/tail"
	"gopkg.in/alecthomas/kingpin.v2"
)

var applicationName = "haproxy-log2span"

var githash = "notprovided"

func main() {
	var err error

	var (
		flagFilename string
	)
	kingpin.Flag("filename", "File to tail").Short('f').Required().StringVar(&flagFilename)
	kingpin.Parse()

	fmt.Printf("haproxy-log2span.githash: %v\n", githash)

	if err = platform.SetupRollbar(applicationName, githash); err != nil {
		panic(err)
	}

	if err := platform.SetupOpentracing(); err != nil {
		rollbar.Error(rollbar.ERR, err)
		panic(err)
	}

	datadogClient, err := platform.SetupDatadog(applicationName, githash)
	if err != nil {
		rollbar.Error(rollbar.ERR, err)
		panic(err)
	}

	parentSpanCB := func(sp opentracing.Span, log lib.HAProxyHTTPLog) error {
		if !strings.HasPrefix(log.CapturedRequestHeaders, "RQ") {
			return fmt.Errorf("No SID provided")
		}
		sp.SetTag("guid:request_sid", log.CapturedRequestHeaders)
		sp.SetTag("peer.zone", network.GetZone(log.ServerName))
		// This needs to be filtered before it can be included.
		// topSpan.SetTag("request", log.request)
		return lib.DefaultParentSpanCB(sp, log)
	}

	haproxyProcessor := lib.NewProcessor(
		lib.WithParentSpanCallback(parentSpanCB),
		lib.WithTimezoneCorrection(8*time.Hour),
	)

	t, err := tail.TailFile(flagFilename,
		tail.Config{Follow: true,
			ReOpen:    true,
			MustExist: true,
			Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}})
	if err != nil {
		rollbar.Error(rollbar.ERR, err)
		panic(fmt.Sprintf("Unable to open file: %v\n", err))
	}
	for line := range t.Lines {
		err := haproxyProcessor.Process(line.Text)
		if err != nil {
			rollbar.Error(rollbar.ERR, err)
			datadogClient.Count("log_not_matched", 1, nil, 1)
		} else {
			datadogClient.Count("log_matched", 1, nil, 1)
		}
	}
}
