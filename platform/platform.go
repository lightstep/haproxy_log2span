package platform

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/lightstep/lightstep-tracer-go"
	"github.com/opentracing/opentracing-go"

	"github.com/DataDog/datadog-go/statsd"

	"github.com/stvp/rollbar"
)

func credBucket() (string, string) {
	realms := map[string]string{ // YARL (yet another realm list)
		"outside":   "outside",
		"corp-us1":  "corp",
		"us1":       "prod",
		"us2":       "prod",
		"ie1":       "prod",
		"au1":       "prod",
		"jp1":       "prod",
		"sg1":       "prod",
		"br1":       "prod",
		"stage-us1": "stage",
		"stage-us2": "stage",
		"stage-au1": "stage",
		"dev-us1":   "dev",
		"dev-us2":   "dev",
	}

	regions := map[string]string{
		"outside": "us-west-1",
		"corp":    "us-east-1",
		"prod":    "us-east-1",
		"stage":   "us-east-1",
		"dev":     "us-east-1",
	}

	env, ok := os.LookupEnv("TWILIO_ACCOUNT")
	if !ok {
		fmt.Printf("Falling back to TWILIO_REALM since TWILIO_ACCOUNT didn't look up (%v)\n", env)

		realm, ok := os.LookupEnv("TWILIO_REALM")
		if !ok {
			fmt.Printf("Falling back to dev since TWILIO_REALM didn't look up (%v)\n", realm)
			env = "dev"
		} else {
			env = realms[realm]
		}
	}

	return fmt.Sprintf("com.twilio.%v.credentials", env), regions[env]
}

func GetCredential(path string, attempts int, backoff int, length int) ([]byte, error) {
	bucket, region := credBucket()
	svc := s3.New(session.New(), aws.NewConfig().WithRegion(region))

	for {
		if attempts < 1 {
			return []byte{}, errors.New("Unable to fetch credentials")
		}

		params := &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(path),
		}

		resp, err := svc.GetObject(params)

		if err != nil {
			fmt.Printf("Fetching credentials from s3 (%v) failed with %v retries left: %v\n", bucket, attempts, err.Error())

		} else {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Fetching credentials from s3 (%v) failed with %v retries left: %v\n", bucket, attempts, err.Error())
			} else if len(body) < length {
				return []byte{}, errors.New("Bad credentials received from s3")
			} else {
				key := body
				if len(body) > length {
					key = key[:length] // attempt at truncation of newline
				}

				return key, nil

				break
			}
		}

		attempts -= 1
		time.Sleep(time.Duration(backoff) * time.Second)
		backoff *= 2
	}

	return []byte{}, errors.New("Unable to fetch credentials")
}

func SetupOpentracing() (err error) {
	key, err := GetCredential("platform/insight/lightstep/lightstep_api_key", 10, 1, 32)
	if err != nil {
		return errors.New("Unable to fetch lightstep api key from credentials bucket")
	}

	realm, ok := os.LookupEnv("TWILIO_REALM")
	if !ok {
		return errors.New("TWILIO_REALM needed for opentracing configuration not found in environment")
	}

	role, ok := os.LookupEnv("TWILIO_ROLES")
	if !ok {
		role = "LookupFailed"
	}

	hostsid, ok := os.LookupEnv("BOXCONFIG_HOST_SID")
	if !ok {
		hostsid = "LookupFailed"
	}

	az, ok := os.LookupEnv("AVAILABILITY_ZONE")
	if !ok {
		az = "LookupFailed"
	}

	collectorDNS := fmt.Sprintf("lightstep.%v.twilio.com", realm)

	tags := opentracing.Tags(map[string]interface{}{
		"realm":     realm,
		"role":      role,
		"host_sid":  hostsid,
		"host.zone": az,
	})

	lightstepTracer := lightstep.NewTracer(lightstep.Options{
		AccessToken: string(key),
		Collector: lightstep.Endpoint{
			Host:      collectorDNS,
			Port:      80,
			Plaintext: true,
		},
		UseGRPC: false,
		Tags:    tags,
	})

	opentracing.InitGlobalTracer(lightstepTracer)

	return nil
}

func SetupDatadog(namespace string, version string) (datadogClient *statsd.Client, err error) {
	const DD_ADDR_C = "127.0.0.1:8126"

	datadogClient, err = statsd.New(DD_ADDR_C)

	if err != nil {
		return &statsd.Client{}, errors.New("Datadog client setup failed")
	}

	// Prefix every metric with the app name
	datadogClient.Namespace = namespace + "."

	datadogClient.Tags = append(datadogClient.Tags, "version:"+version)
	return datadogClient, nil
}

func SetupRollbar(keyname string, version string) (err error) {
	key, err := GetCredential("platform/insight/rollbar/"+keyname, 10, 1, 32)
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to fetch rollbar api key for %v from credentials bucket", keyname))
	}

	rollbar.Token = string(key)
	rollbar.CodeVersion = version

	env, ok := os.LookupEnv("TWILIO_ACCOUNT")
	if !ok {
		fmt.Printf("TWILIO_ACCOUNT not available in environment, defaulting to unknown (%v)\n", env)

		rollbar.Environment = "unknown"
	} else {
		rollbar.Environment = env
	}

	return nil
}
