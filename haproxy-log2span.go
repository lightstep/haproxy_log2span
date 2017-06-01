package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lightstep/haproxy_log2span/lib"
	lightstep "github.com/lightstep/lightstep-tracer-go"
	opentracing "github.com/opentracing/opentracing-go"

	"github.com/hpcloud/tail"
	"gopkg.in/alecthomas/kingpin.v2"
)

var applicationName = "haproxy-log2span"

var githash = "notprovided"

func main() {
	var err error

	var (
		flagFilename string
		accessToken  string
	)
	kingpin.Flag("filename", "File to tail").Short('f').Required().StringVar(&flagFilename)
	kingpin.Flag("access_token", "LS access token").Short('t').Required().StringVar(&accessToken)
	kingpin.Parse()

	fmt.Printf("haproxy-log2span.githash: %v\n", githash)

	lightstepTracer := lightstep.NewTracer(lightstep.Options{
		AccessToken: accessToken,
	})

	opentracing.InitGlobalTracer(lightstepTracer)

	parentSpanCB := func(sp opentracing.Span, log lib.HAProxyHTTPLog) error {
		if !strings.HasPrefix(log.CapturedRequestHeaders, "RQ") {
			return fmt.Errorf("No SID provided")
		}
		sp.SetTag("guid:request_sid", log.CapturedRequestHeaders)
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
		panic(fmt.Sprintf("Unable to open file: %v\n", err))
	}
	for line := range t.Lines {
		err := haproxyProcessor.Process(line.Text)
		if err != nil {
		}
	}
}
