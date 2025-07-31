package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the admission gateway
type Metrics struct {
	// Request metrics
	RequestsTotal    prometheus.Counter
	RequestsAllowed  prometheus.Counter
	RequestsRejected *prometheus.CounterVec
	RequestDuration  prometheus.Histogram

	// Agent metrics
	AgentDuration   *prometheus.HistogramVec
	AgentErrors     *prometheus.CounterVec
	AgentRejections *prometheus.CounterVec

	// System metrics
	RegisteredAgents prometheus.Gauge
}

// NewMetrics creates and registers all Prometheus metrics
func NewMetrics() *Metrics {
	return &Metrics{
		// Request metrics
		RequestsTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "admeshion_requests_total",
			Help: "Total number of admission requests processed",
		}),

		RequestsAllowed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "admeshion_requests_allowed_total",
			Help: "Total number of admission requests allowed",
		}),

		RequestsRejected: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "admeshion_requests_rejected_total",
			Help: "Total number of admission requests rejected",
		}, []string{"reason"}),

		RequestDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "admeshion_request_duration_seconds",
			Help:    "Duration of admission request processing",
			Buckets: prometheus.DefBuckets,
		}),

		// Agent metrics
		AgentDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "admeshion_agent_duration_seconds",
			Help:    "Duration of individual agent processing",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"agent"}),

		AgentErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "admeshion_agent_errors_total",
			Help: "Total number of agent errors",
		}, []string{"agent"}),

		AgentRejections: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "admeshion_agent_rejections_total",
			Help: "Total number of rejections by agent",
		}, []string{"agent"}),

		// System metrics
		RegisteredAgents: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "admeshion_registered_agents",
			Help: "Number of registered admission agents",
		}),
	}
}

// UpdateRegisteredAgents updates the count of registered agents
func (m *Metrics) UpdateRegisteredAgents(count int) {
	m.RegisteredAgents.Set(float64(count))
}
