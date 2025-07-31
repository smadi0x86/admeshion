package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/admeshion/admission-mesh/pkg/mesh"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Enforce labels on k8s resources

type LabelPolicyAgent struct {
	name            string
	requiredLabels  map[string]*LabelRequirement
	forbiddenLabels []string
	labelValueRegex map[string]*regexp.Regexp
}

type LabelRequirement struct {
	Key           string   `json:"key"`
	Required      bool     `json:"required"`
	AllowedValues []string `json:"allowed_values,omitempty"`
	Pattern       string   `json:"pattern,omitempty"`
	Description   string   `json:"description,omitempty"`
}

type LabelPolicyConfig struct {
	RequiredLabels  []LabelRequirement `json:"required_labels,omitempty"`
	ForbiddenLabels []string           `json:"forbidden_labels,omitempty"`
}

// NewLabelPolicyAgent creates a new label policy agent with default configuration
func NewLabelPolicyAgent() *LabelPolicyAgent {
	agent := &LabelPolicyAgent{
		name:            "label-policy-agent",
		requiredLabels:  make(map[string]*LabelRequirement),
		forbiddenLabels: make([]string, 0),
		labelValueRegex: make(map[string]*regexp.Regexp),
	}

	// Default required labels
	defaultRequirements := []LabelRequirement{
		{
			Key:         "app",
			Required:    true,
			Pattern:     "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
			Description: "Application name using DNS-1123 format",
		},
		{
			Key:         "version",
			Required:    true,
			Pattern:     "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+[0-9A-Za-z-]+)?$",
			Description: "Semantic version (e.g., v1.2.3)",
		},
		{
			Key:           "environment",
			Required:      true,
			AllowedValues: []string{"development", "staging", "production", "test"},
			Description:   "Deployment environment",
		},
		{
			Key:         "team",
			Required:    true,
			Pattern:     "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
			Description: "Owning team name",
		},
	}

	// Default forbidden labels
	agent.forbiddenLabels = []string{
		"kubernetes.io/managed-by", // Reserved for system
		"internal-secret",
		"debug-mode",
	}

	// Loop on default requirements and add them to the agent
	for _, req := range defaultRequirements {
		agent.AddRequirement(req)
	}

	return agent
}

// NewLabelPolicyAgentWithConfig creates an agent with custom configuration
func NewLabelPolicyAgentWithConfig(config LabelPolicyConfig) *LabelPolicyAgent {
	agent := &LabelPolicyAgent{
		name:            "label-policy-agent",
		requiredLabels:  make(map[string]*LabelRequirement),
		forbiddenLabels: config.ForbiddenLabels,
		labelValueRegex: make(map[string]*regexp.Regexp),
	}

	for _, req := range config.RequiredLabels {
		agent.AddRequirement(req)
	}

	return agent
}

// AddRequirement adds a label requirement to the agent
func (l *LabelPolicyAgent) AddRequirement(req LabelRequirement) error {
	// Compile regex pattern if provided
	if req.Pattern != "" {
		regex, err := regexp.Compile(req.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern for label %s: %v", req.Key, err)
		}
		l.labelValueRegex[req.Key] = regex
	}

	// Store requirement
	reqCopy := req
	l.requiredLabels[req.Key] = &reqCopy

	return nil
}

// Name returns the agent name
func (l *LabelPolicyAgent) Name() string {
	return l.name
}

// check if the agent can handle the request
func (l *LabelPolicyAgent) CanHandle(req admissionv1.AdmissionRequest) bool {
	// Handle multiple resource types that support labels
	// TODO: Are there any other resource types that support labels?
	supportedKinds := []string{
		"Pod",
		"Deployment",
		"Service",
		"ConfigMap",
		"Secret",
		"DaemonSet",
		"StatefulSet",
		"Job",
		"CronJob",
	}

	for _, kind := range supportedKinds {
		if req.Kind.Kind == kind &&
			(req.Operation == admissionv1.Create || req.Operation == admissionv1.Update) {
			return true
		}
	}

	return false
}

// handle the request
func (l *LabelPolicyAgent) Handle(ctx context.Context, req admissionv1.AdmissionRequest) (mesh.AgentDecision, error) {
	// Extract labels based on resource kind
	labels, err := l.extractLabels(req)
	if err != nil {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Failed to extract labels: %v", err),
			Code:    400,
		}, nil
	}

	if decision := l.checkRequiredLabels(labels, req.Kind.Kind); !decision.Allowed {
		return decision, nil
	}

	if decision := l.checkForbiddenLabels(labels, req.Kind.Kind); !decision.Allowed {
		return decision, nil
	}

	if decision := l.validateLabelValues(labels, req.Kind.Kind); !decision.Allowed {
		return decision, nil
	}

	// All label policies passed, congrats!
	return mesh.AgentDecision{
		Allowed: true,
		Reason:  fmt.Sprintf("%s meets label policy requirements", req.Kind.Kind),
		Code:    200,
	}, nil
}

// extractLabels extracts labels from different resource types
func (l *LabelPolicyAgent) extractLabels(req admissionv1.AdmissionRequest) (map[string]string, error) {
	var obj metav1.Object

	switch req.Kind.Kind {
	case "Pod":
		pod := &corev1.Pod{}
		if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
			return nil, err
		}
		obj = pod
	case "Service":
		svc := &corev1.Service{}
		if err := json.Unmarshal(req.Object.Raw, svc); err != nil {
			return nil, err
		}
		obj = svc
	case "ConfigMap":
		cm := &corev1.ConfigMap{}
		if err := json.Unmarshal(req.Object.Raw, cm); err != nil {
			return nil, err
		}
		obj = cm
	case "Secret":
		secret := &corev1.Secret{}
		if err := json.Unmarshal(req.Object.Raw, secret); err != nil {
			return nil, err
		}
		obj = secret
	default:
		// For other types, try to extract as generic metav1.Object
		objMap := make(map[string]interface{})
		if err := json.Unmarshal(req.Object.Raw, &objMap); err != nil {
			return nil, err
		}

		metadata, exists := objMap["metadata"].(map[string]interface{})
		if !exists {
			return make(map[string]string), nil
		}

		labels, exists := metadata["labels"].(map[string]interface{})
		if !exists {
			return make(map[string]string), nil
		}

		result := make(map[string]string)
		for k, v := range labels {
			if strVal, ok := v.(string); ok {
				result[k] = strVal
			}
		}
		return result, nil
	}

	labels := obj.GetLabels()
	if labels == nil {
		return make(map[string]string), nil
	}

	return labels, nil
}

// checkRequiredLabels validates that all required labels are present
func (l *LabelPolicyAgent) checkRequiredLabels(labels map[string]string, kind string) mesh.AgentDecision {
	var missingLabels []string

	for key, requirement := range l.requiredLabels {
		if !requirement.Required {
			continue
		}

		value, exists := labels[key]
		if !exists {
			missingLabels = append(missingLabels, key)
			continue
		}

		// Check allowed values if specified
		if len(requirement.AllowedValues) > 0 {
			allowed := false
			for _, allowedValue := range requirement.AllowedValues {
				if value == allowedValue {
					allowed = true
					break
				}
			}
			if !allowed {
				return mesh.AgentDecision{
					Allowed: false,
					Reason: fmt.Sprintf("%s label '%s' has value '%s' but must be one of: %s",
						kind, key, value, strings.Join(requirement.AllowedValues, ", ")),
					Code: 403,
				}
			}
		}
	}

	if len(missingLabels) > 0 {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("%s is missing required labels: %s", kind, strings.Join(missingLabels, ", ")),
			Code:    403,
		}
	}

	return mesh.AgentDecision{Allowed: true}
}

// checkForbiddenLabels ensures no forbidden labels are present
func (l *LabelPolicyAgent) checkForbiddenLabels(labels map[string]string, kind string) mesh.AgentDecision {
	for _, forbidden := range l.forbiddenLabels {
		if _, exists := labels[forbidden]; exists {
			return mesh.AgentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("%s contains forbidden label: %s", kind, forbidden),
				Code:    403,
			}
		}
	}
	return mesh.AgentDecision{Allowed: true}
}

// validateLabelValues validates label values against regex patterns
func (l *LabelPolicyAgent) validateLabelValues(labels map[string]string, kind string) mesh.AgentDecision {
	for key, value := range labels {
		if regex, exists := l.labelValueRegex[key]; exists {
			if !regex.MatchString(value) {
				requirement := l.requiredLabels[key]
				description := ""
				if requirement != nil && requirement.Description != "" {
					description = fmt.Sprintf(" (%s)", requirement.Description)
				}

				return mesh.AgentDecision{
					Allowed: false,
					Reason: fmt.Sprintf("%s label '%s' has invalid value '%s'%s",
						kind, key, value, description),
					Code: 403,
				}
			}
		}
	}
	return mesh.AgentDecision{Allowed: true}
}
