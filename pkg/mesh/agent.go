package mesh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
)

// AdmissionAgent defines the interface that all admission agents must implement

type AdmissionAgent interface {
	// Name returns the unique name of the agent
	Name() string

	// CanHandle determines if this agent should process the given admission request
	CanHandle(req admissionv1.AdmissionRequest) bool

	// Handle processes the admission request and returns a decision
	Handle(ctx context.Context, req admissionv1.AdmissionRequest) (AgentDecision, error)
}

type AgentDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Code    int32  `json:"code"` // 200, 400, 403, 500 ...
}

type AgentResult struct {
	AgentName string        `json:"agent_name"`
	Decision  AgentDecision `json:"decision"`
	Duration  time.Duration `json:"duration"`
	Error     error         `json:"error,omitempty"`
}

// Registry manages registered admission agents
type Registry struct {
	agents []AdmissionAgent
	logger *zap.Logger
	mu     sync.RWMutex
}

func NewRegistry(logger *zap.Logger) *Registry {
	return &Registry{
		agents: make([]AdmissionAgent, 0),
		logger: logger,
	}
}

func (r *Registry) Register(agent AdmissionAgent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate names
	for _, existing := range r.agents {
		if existing.Name() == agent.Name() {
			return fmt.Errorf("agent with name %s already registered", agent.Name())
		}
	}

	r.agents = append(r.agents, agent)
	r.logger.Info("Registered admission agent", zap.String("name", agent.Name()))
	return nil
}

func (r *Registry) GetAgents() []AdmissionAgent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to prevent external modification
	agents := make([]AdmissionAgent, len(r.agents))
	copy(agents, r.agents)
	return agents
}

// GetApplicableAgents returns agents that can handle the given request
func (r *Registry) GetApplicableAgents(req admissionv1.AdmissionRequest) []AdmissionAgent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var applicable []AdmissionAgent
	for _, agent := range r.agents {
		if agent.CanHandle(req) {
			applicable = append(applicable, agent)
		}
	}
	return applicable
}

func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents)
}
