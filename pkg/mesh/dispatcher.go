package mesh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
)

// Dispatcher handles the orchestration of agent calls for admission requests

type Dispatcher struct {
	registry    *Registry
	logger      *zap.Logger
	timeout     time.Duration
	maxParallel int
}

func NewDispatcher(registry *Registry, logger *zap.Logger, timeout time.Duration, maxParallel int) *Dispatcher {
	return &Dispatcher{
		registry:    registry,
		logger:      logger,
		timeout:     timeout,
		maxParallel: maxParallel,
	}
}

type DispatchResult struct {
	Allowed    bool          `json:"allowed"`
	Reason     string        `json:"reason"`
	Code       int32         `json:"code"`
	AgentCount int           `json:"agent_count"`
	Results    []AgentResult `json:"results"`
	Duration   time.Duration `json:"duration"`
}

// Dispatch sends the admission request to all applicable agents and aggregates results
func (d *Dispatcher) Dispatch(ctx context.Context, req admissionv1.AdmissionRequest) *DispatchResult {
	start := time.Now()

	// Get applicable agents
	agents := d.registry.GetApplicableAgents(req)
	if len(agents) == 0 {
		d.logger.Debug("No applicable agents found for request",
			zap.String("kind", req.Kind.Kind),
			zap.String("namespace", req.Namespace),
			zap.String("name", req.Name))

		return &DispatchResult{
			Allowed:    true,
			Reason:     "No applicable agents",
			Code:       200,
			AgentCount: 0,
			Results:    []AgentResult{},
			Duration:   time.Since(start),
		}
	}

	d.logger.Info("Dispatching admission request to agents",
		zap.String("kind", req.Kind.Kind),
		zap.String("namespace", req.Namespace),
		zap.String("name", req.Name),
		zap.Int("agent_count", len(agents)))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Channel to collect results
	resultsChan := make(chan AgentResult, len(agents))

	// Semaphore to limit parallel executions
	sem := make(chan struct{}, d.maxParallel)

	// WaitGroup to wait for all goroutines
	var wg sync.WaitGroup

	// Launch agent calls in parallel
	for _, agent := range agents {
		wg.Add(1)
		go func(a AdmissionAgent) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			result := d.callAgent(ctx, a, req)
			resultsChan <- result
		}(agent)
	}

	// Wait for all agents to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	var results []AgentResult
	allowed := true
	var denyReason string
	var denyCode int32

	for result := range resultsChan {
		results = append(results, result)

		// Log individual agent result
		if result.Error != nil {
			d.logger.Error("Agent returned error",
				zap.String("agent", result.AgentName),
				zap.Error(result.Error),
				zap.Duration("duration", result.Duration))
			// Treat errors as deny for safety
			allowed = false
			if denyReason == "" {
				denyReason = fmt.Sprintf("Agent %s failed: %v", result.AgentName, result.Error)
				denyCode = 500
			}
		} else {
			d.logger.Info("Agent decision",
				zap.String("agent", result.AgentName),
				zap.Bool("allowed", result.Decision.Allowed),
				zap.String("reason", result.Decision.Reason),
				zap.Int32("code", result.Decision.Code),
				zap.Duration("duration", result.Duration))

			// If any agent denies, the overall decision is deny
			if !result.Decision.Allowed {
				allowed = false
				if denyReason == "" {
					denyReason = result.Decision.Reason
					denyCode = result.Decision.Code
				}
			}
		}
	}

	// Build final result
	finalReason := "All agents allowed"
	finalCode := int32(200)

	if !allowed {
		finalReason = denyReason
		finalCode = denyCode
	}

	return &DispatchResult{
		Allowed:    allowed,
		Reason:     finalReason,
		Code:       finalCode,
		AgentCount: len(agents),
		Results:    results,
		Duration:   time.Since(start),
	}
}

// callAgent executes a single agent and captures timing and error information
func (d *Dispatcher) callAgent(ctx context.Context, agent AdmissionAgent, req admissionv1.AdmissionRequest) AgentResult {
	start := time.Now()

	decision, err := agent.Handle(ctx, req)
	duration := time.Since(start)

	return AgentResult{
		AgentName: agent.Name(),
		Decision:  decision,
		Duration:  duration,
		Error:     err,
	}
}
