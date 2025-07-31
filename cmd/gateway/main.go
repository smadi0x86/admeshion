package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/admeshion/admission-mesh/internal/agents"
	"github.com/admeshion/admission-mesh/pkg/mesh"
	"github.com/admeshion/admission-mesh/pkg/observability"
)

const (
	defaultPort        = "8443"
	defaultCertPath    = "/etc/certs/tls.crt"
	defaultKeyPath     = "/etc/certs/tls.key"
	defaultTimeout     = 10 * time.Second
	defaultMaxParallel = 10
	metricsPort        = "8080"
)

// GatewayServer represents the admission gateway server
type GatewayServer struct {
	logger     *zap.Logger
	registry   *mesh.Registry
	dispatcher *mesh.Dispatcher
	metrics    *observability.Metrics
	server     *http.Server
}

// Config holds the gateway server configuration
type Config struct {
	Port        string
	CertPath    string
	KeyPath     string
	Timeout     time.Duration
	MaxParallel int
	LogLevel    string
}

func main() {
	// get config from env vars
	config := parseConfig()

	// init logger
	logger := initLogger(config.LogLevel)
	defer logger.Sync()

	logger.Info("Starting Admission Gateway",
		zap.String("port", config.Port),
		zap.String("cert_path", config.CertPath),
		zap.String("key_path", config.KeyPath),
		zap.Duration("timeout", config.Timeout),
		zap.Int("max_parallel", config.MaxParallel))

	// init metrics
	metrics := observability.NewMetrics()

	// create agent registry
	registry := mesh.NewRegistry(logger)

	// register agents
	if err := registerAgents(registry, logger); err != nil {
		logger.Fatal("Failed to register agents", zap.Error(err))
	}

	dispatcher := mesh.NewDispatcher(registry, logger, config.Timeout, config.MaxParallel)

	gateway := &GatewayServer{
		logger:     logger,
		registry:   registry,
		dispatcher: dispatcher,
		metrics:    metrics,
	}

	router := mux.NewRouter()
	router.HandleFunc("/validate", gateway.validateHandler).Methods("POST")
	router.HandleFunc("/health", gateway.healthHandler).Methods("GET")
	router.HandleFunc("/ready", gateway.readyHandler).Methods("GET")

	gateway.server = &http.Server{
		Addr:         ":" + config.Port,
		Handler:      router,
		TLSConfig:    &tls.Config{},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start metrics server in background
	go startMetricsServer(logger, metrics)

	// Start server in background
	go func() {
		logger.Info("Starting HTTPS server", zap.String("addr", gateway.server.Addr))
		if err := gateway.server.ListenAndServeTLS(config.CertPath, config.KeyPath); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := gateway.server.Shutdown(ctx); err != nil {
		logger.Error("Server shutdown failed", zap.Error(err))
	} else {
		logger.Info("Server shutdown complete")
	}
}

// parseConfig parses configuration from environment variables
func parseConfig() Config {
	config := Config{
		Port:        getEnvOrDefault("PORT", defaultPort),
		CertPath:    getEnvOrDefault("CERT_PATH", defaultCertPath),
		KeyPath:     getEnvOrDefault("KEY_PATH", defaultKeyPath),
		Timeout:     parseTimeoutOrDefault("TIMEOUT", defaultTimeout),
		MaxParallel: parseIntOrDefault("MAX_PARALLEL", defaultMaxParallel),
		LogLevel:    getEnvOrDefault("LOG_LEVEL", "info"),
	}
	return config
}

// validateHandler handles admission validation requests
func (g *GatewayServer) validateHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	g.metrics.RequestsTotal.Inc()

	// Parse admission review
	var admissionReview admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&admissionReview); err != nil {
		g.logger.Error("Failed to decode admission review", zap.Error(err))
		g.metrics.RequestsRejected.WithLabelValues("decode_error").Inc()
		http.Error(w, fmt.Sprintf("Failed to decode admission review: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	req := admissionReview.Request
	if req == nil {
		g.logger.Error("Admission review request is nil")
		g.metrics.RequestsRejected.WithLabelValues("nil_request").Inc()
		http.Error(w, "Admission review request is nil", http.StatusBadRequest)
		return
	}

	g.logger.Info("Processing admission request",
		zap.String("uid", string(req.UID)),
		zap.String("kind", req.Kind.Kind),
		zap.String("namespace", req.Namespace),
		zap.String("name", req.Name),
		zap.String("operation", string(req.Operation)))

	// Dispatch to agents
	result := g.dispatcher.Dispatch(r.Context(), *req)

	// Build admission response
	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: result.Allowed,
		Result:  &metav1.Status{},
	}

	if !result.Allowed {
		response.Result = &metav1.Status{
			Code:    result.Code,
			Message: result.Reason,
		}
		g.logger.Warn("Request denied",
			zap.String("uid", string(req.UID)),
			zap.String("reason", result.Reason),
			zap.Int32("code", result.Code),
			zap.Int("agent_count", result.AgentCount),
			zap.Duration("duration", result.Duration))

		g.metrics.RequestsRejected.WithLabelValues("policy_violation").Inc()
	} else {
		g.logger.Info("Request allowed",
			zap.String("uid", string(req.UID)),
			zap.Int("agent_count", result.AgentCount),
			zap.Duration("duration", result.Duration))

		g.metrics.RequestsAllowed.Inc()
	}

	// Update metrics for individual agents
	for _, agentResult := range result.Results {
		g.metrics.AgentDuration.WithLabelValues(agentResult.AgentName).Observe(agentResult.Duration.Seconds())
		if agentResult.Error != nil {
			g.metrics.AgentErrors.WithLabelValues(agentResult.AgentName).Inc()
		}
		if !agentResult.Decision.Allowed {
			g.metrics.AgentRejections.WithLabelValues(agentResult.AgentName).Inc()
		}
	}

	// Create admission review response
	admissionResponse := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: response,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(admissionResponse); err != nil {
		g.logger.Error("Failed to encode admission response", zap.Error(err))
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}

	// Record overall request duration
	g.metrics.RequestDuration.Observe(time.Since(start).Seconds())
}

// healthHandler handles health check requests
func (g *GatewayServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// readyHandler handles readiness check requests
func (g *GatewayServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	if g.registry.Count() == 0 {
		http.Error(w, "No agents registered", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Ready - %d agents registered", g.registry.Count())))
}

// registerAgents registers all available agents
func registerAgents(registry *mesh.Registry, logger *zap.Logger) error {
	// Register PodSecurityAgent
	podSecurityAgent := agents.NewPodSecurityAgent()
	if err := registry.Register(podSecurityAgent); err != nil {
		return fmt.Errorf("failed to register pod security agent: %w", err)
	}

	// Register ImagePolicyAgent
	imagePolicyAgent := agents.NewImagePolicyAgent()
	if err := registry.Register(imagePolicyAgent); err != nil {
		return fmt.Errorf("failed to register image policy agent: %w", err)
	}

	// Register LabelPolicyAgent
	labelPolicyAgent := agents.NewLabelPolicyAgent()
	if err := registry.Register(labelPolicyAgent); err != nil {
		return fmt.Errorf("failed to register label policy agent: %w", err)
	}

	logger.Info("Successfully registered all agents", zap.Int("count", 3))
	return nil
}

// startMetricsServer starts the Prometheus metrics server
// TODO: use observability metrics
func startMetricsServer(logger *zap.Logger, metrics *observability.Metrics) {
	metricsRouter := mux.NewRouter()
	metricsRouter.Handle("/metrics", promhttp.Handler())

	metricsServer := &http.Server{
		Addr:    ":" + metricsPort,
		Handler: metricsRouter,
	}

	logger.Info("Starting metrics server", zap.String("port", metricsPort))
	if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Metrics server failed", zap.Error(err))
	}
}

// initLogger initializes the zap logger
func initLogger(level string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)

	logger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	return logger
}

// Helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseTimeoutOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func parseIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed := parseInt(value); parsed > 0 {
			return parsed
		}
	}
	return defaultValue
}

func parseInt(s string) int {
	result := 0
	for _, char := range s {
		if char >= '0' && char <= '9' {
			result = result*10 + int(char-'0')
		} else {
			return -1
		}
	}
	return result
}
