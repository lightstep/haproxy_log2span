package main

import (
	"fmt"
	"os"

	"github.com/lightstep/haproxy_log2span/lib"
	"github.com/lightstep/haproxy_log2span/platform"
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

	err = platform.SetupRollbar(applicationName, githash)
	if err != nil {
		panic(err)
	}

	err = platform.SetupOpentracing()
	if err != nil {
		rollbar.Error(rollbar.ERR, err)
		panic(err)
	}

	datadogClient, err := platform.SetupDatadog(applicationName, githash)
	if err != nil {
		rollbar.Error(rollbar.ERR, err)
		panic(err)
	}

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
		err := lib.ProcessLine(line.Text)
		if err != nil {
			rollbar.Error(rollbar.ERR, err)
			datadogClient.Count("log_not_matched", 1, nil, 1)
		} else {
			datadogClient.Count("log_matched", 1, nil, 1)
		}
	}
}
