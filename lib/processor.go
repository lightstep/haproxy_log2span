package lib

import (
	"net"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

// SpanCallback allows you to customize a span with the parsed
// HAProxy log. Do not finish the span in this callback. An error can be
// returned to cancel processing the log.
type SpanCallback func(sp opentracing.Span, log HAProxyHTTPLog) error

type ProcessorOption func(*Processor)

// WithParentSpanCallback returns a ProcessorOption that specifies a SpanCallback
// to be applied to the parent span of the log. Defaults to DefaultProcessorCB.
func WithParentSpanCallback(cb SpanCallback) ProcessorOption {
	return func(p *Processor) {
		p.parentSpanCallback = cb
	}
}

// WithTimezoneCorrection specifies the amount of time to add to the parsed
// timestamp.
func WithTimezoneCorrection() ProcessorOption {
	return func(p *Processor) {
		ticker := time.NewTicker(time.Millisecond * 1000)
		go func() {
			for t := range ticker.C {
				_, rawOffset := t.Zone()
				// Need to reverse the offset to get back to UTC
				p.timezoneCorrection = time.Duration(-rawOffset) * time.Second
			}
		}()
	}
}

// WithTracer returns a Processor that specifies the opentracing tracer to be used.
// Defaults to the global tracer.
func WithTracer(tracer opentracing.Tracer) ProcessorOption {
	return func(p *Processor) {
		p.tracer = tracer
	}
}

// WithSpanContextInterceptor returns a ProcessorOption that specifies a function
// which returns an opentracing.SpanContext from the parsed log info. The
// returned SpanContext is used to create a ChildOf reference if valid.
func WithSpanContextExtractor(extractor func(log HAProxyHTTPLog) opentracing.SpanContext) ProcessorOption {
	return func(p *Processor) {
		p.scExtractor = extractor
	}
}

type Processor struct {
	tracer             opentracing.Tracer
	parentSpanCallback SpanCallback
	timezoneCorrection time.Duration
	scExtractor        func(HAProxyHTTPLog) opentracing.SpanContext
}

func NewProcessor(opts ...func(*Processor)) Processor {
	var p Processor
	for _, opt := range opts {
		opt(&p)
	}

	if p.tracer == nil {
		p.tracer = opentracing.GlobalTracer()
	}
	if p.parentSpanCallback == nil {
		p.parentSpanCallback = DefaultParentSpanCB
	}

	return p
}

func DefaultParentSpanCB(sp opentracing.Span, log HAProxyHTTPLog) error {
	if ip := net.ParseIP(log.ServerName); ip != nil {
		if ip.To4() != nil {
			sp.SetTag("peer.ipv4", log.ServerName)
		} else if ip.To16() != nil {
			sp.SetTag("peer.ipv6", log.ServerName)
		}
	}
	sp.SetTag("retries", log.Retries)
	sp.SetTag("f_end", log.FrontendName)
	sp.SetTag("b_end", log.BackendName)
	sp.SetTag("bytes", log.BytesRead)
	sp.SetTag("srv_queue", log.SrvQueue)
	sp.SetTag("backend_queue", log.BackendQueue)
	ext.HTTPStatusCode.Set(sp, log.StatusCode)
	if log.StatusCode >= 500 {
		ext.Error.Set(sp, true)
	}
	sp.SetTag("http.status_class", ParseStatusClass(log.StatusCode))
	return nil
}
