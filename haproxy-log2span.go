package main

import (
	"fmt"
	"os"
	"regexp"

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

	haproxyRegex := `^(?P<syslog_time>[^ ]* +[^ ]* +[^ ]*) (?P<syslog_host>[\w\-\.]+) (?P<ps>\w+)\[(?P<pid>\d+)\]: ((?P<c_ip>[\w\.]+):(?P<c_port>\d+) \[(?P<timestamp>.+)\] (?P<f_end>[\w\~\-]+) (?P<b_end>[\w\-]+)\/(?P<b_server>[\w\.\-]+) (?P<tq>\-?\d+)\/(?P<tw>\-?\d+)\/(?P<tc>\-?\d+)\/(?P<tr>\-?\d+)\/\+?(?P<tt>\d+) (?P<status_code>\d+) \+?(?P<bytes>\d+) (?P<req_cookie>\S?) (?P<res_cookie>\S?) (?P<t_state>[\w\-]+) (?P<actconn>\d+)\/(?P<feconn>\d+)\/(?P<beconn>\d+)\/(?P<srv_conn>\d+)\/\+?(?P<retries>\d+) (?P<srv_queue>\d+)\/(?P<backend_queue>\d+) (\{(?P<req_headers>[^}]*)\} )?(\{?(?P<res_headers>[^}]*)\}? )?"(?P<request>[^"]*)"?)`

	var compiledRegex *regexp.Regexp
	compiledRegex, err = regexp.Compile(haproxyRegex)
	if err != nil {
		rollbar.Error(rollbar.ERR, err)
		panic(fmt.Sprintf("regexp returned error: %v\n", err.Error()))
	}

	for line := range t.Lines {
		lib.ProcessLine(line.Text, compiledRegex, datadogClient)
	}
}
