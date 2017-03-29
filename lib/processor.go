package lib

import (
	"net"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
)

// SpanCallback allows you to customize a span with the parsed
// HAProxy log. Do not finish the span in this callback. An error can be
// returned to cancel processing the log.
type SpanCallback func(sp opentracing.Span, log HAProxyHTTPLog) error

type ProcessorOption func(*Processor)

type Processor struct {
	tracer             opentracing.Tracer
	parentSpanCallback SpanCallback
}

// WithParentSpanCallback returns a ProcessorOption that specifies a SpanCallback
// to be applied to the parent span of the log.
func WithParentSpanCallback(cb SpanCallback) ProcessorOption {
	return func(p *Processor) {
		p.parentSpanCallback = cb
	}
}

// WithTracer returns a Processor that specifies the opentracing tracer to be used.
// Defaults to the global tracer.
func WithTracer(tracer opentracing.Tracer) ProcessorOption {
	return func(p *Processor) {
		p.tracer = tracer
	}
}

func NewProcessor(opts ...func(*Processor)) Processor {
	var processor Processor
	for _, opt := range opts {
		opt(&processor)
	}

	if processor.tracer == nil {
		processor.tracer = opentracing.GlobalTracer()
	}
	if processor.parentSpanCallback == nil {
		processor.parentSpanCallback = DefaultProcessorCB
	}

	return processor
}

func DefaultProcessorCB(sp opentracing.Span, log HAProxyHTTPLog) error {
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
