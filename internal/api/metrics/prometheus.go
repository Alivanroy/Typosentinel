package metrics

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	prom "github.com/prometheus/client_golang/prometheus"
)

var (
	httpRequestsTotal = prom.NewCounterVec(prom.CounterOpts{
		Name: "typosentinel_http_requests_total",
		Help: "Total HTTP requests",
	}, []string{"path", "method", "status"})

	httpRequestDuration = prom.NewHistogramVec(prom.HistogramOpts{
		Name:    "typosentinel_http_request_duration_seconds",
		Help:    "HTTP request durations",
		Buckets: prom.DefBuckets,
	}, []string{"path"})

	rateLimitHitsTotal = prom.NewCounterVec(prom.CounterOpts{
		Name: "typosentinel_rate_limit_hits_total",
		Help: "Rate limit hits",
	}, []string{"path"})

	webhookSigFailuresTotal = prom.NewCounterVec(prom.CounterOpts{
		Name: "typosentinel_webhook_signature_failures_total",
		Help: "Webhook signature failures",
	}, []string{"provider"})

	webhookReplayBlockedTotal = prom.NewCounterVec(prom.CounterOpts{
		Name: "typosentinel_webhook_replay_blocked_total",
		Help: "Webhook replay blocks",
	}, []string{"provider"})

	redisConnected = prom.NewGauge(prom.GaugeOpts{
		Name: "typosentinel_redis_connected",
		Help: "Redis connection state",
	})

	webhookProviderEnabled = prom.NewGaugeVec(prom.GaugeOpts{
		Name: "typosentinel_webhook_provider_enabled",
		Help: "Webhook provider enabled state",
	}, []string{"provider"})

	webhookProviderSignatureConfigured = prom.NewGaugeVec(prom.GaugeOpts{
		Name: "typosentinel_webhook_provider_signature_configured",
		Help: "Webhook provider signature configured",
	}, []string{"provider"})
)

func init() {
	prom.MustRegister(httpRequestsTotal)
	prom.MustRegister(httpRequestDuration)
	prom.MustRegister(rateLimitHitsTotal)
	prom.MustRegister(webhookSigFailuresTotal)
	prom.MustRegister(webhookReplayBlockedTotal)
	prom.MustRegister(redisConnected)
	prom.MustRegister(webhookProviderEnabled)
	prom.MustRegister(webhookProviderSignatureConfigured)
}

func PrometheusMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(rw, r)
			path := r.URL.Path
			httpRequestsTotal.WithLabelValues(path, r.Method, http.StatusText(rw.status)).Inc()
			httpRequestDuration.WithLabelValues(path).Observe(time.Since(start).Seconds())
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }

func RecordRateLimitHit(path string) {
	rateLimitHitsTotal.WithLabelValues(path).Inc()
}

func RecordWebhookSigFailure(provider string) {
	webhookSigFailuresTotal.WithLabelValues(provider).Inc()
}

func RecordWebhookReplayBlocked(provider string) {
	webhookReplayBlockedTotal.WithLabelValues(provider).Inc()
}

func SetRedisConnected(ok bool) {
	if ok {
		redisConnected.Set(1)
	} else {
		redisConnected.Set(0)
	}
}

func SetWebhookProviderEnabled(provider string, enabled bool) {
	if enabled {
		webhookProviderEnabled.WithLabelValues(provider).Set(1)
	} else {
		webhookProviderEnabled.WithLabelValues(provider).Set(0)
	}
}

func SetWebhookProviderSignatureConfigured(provider string, configured bool) {
	if configured {
		webhookProviderSignatureConfigured.WithLabelValues(provider).Set(1)
	} else {
		webhookProviderSignatureConfigured.WithLabelValues(provider).Set(0)
	}
}
