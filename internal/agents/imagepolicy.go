package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/admeshion/admission-mesh/pkg/mesh"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

type ImagePolicyAgent struct {
	name              string
	allowedRegistries []string
	blockedRegistries []string
	requireDigest     bool
	blockLatestTag    bool
}

type ImagePolicyConfig struct {
	AllowedRegistries []string `json:"allowed_registries,omitempty"`
	BlockedRegistries []string `json:"blocked_registries,omitempty"`
	RequireDigest     bool     `json:"require_digest,omitempty"`
	BlockLatestTag    bool     `json:"block_latest_tag,omitempty"`
}

func NewImagePolicyAgent() *ImagePolicyAgent {
	return &ImagePolicyAgent{
		name: "image-policy-agent",
		// Default allowed registries, can be configured via CRD later
		allowedRegistries: []string{
			"docker.io/library",
			"k8s.gcr.io",
			"registry.k8s.io",
			"quay.io",
			"gcr.io",
		},
		blockedRegistries: []string{
			"docker.io/malicious",
			"untrusted-registry.com",
		},
		requireDigest:  false, // https://cloud.google.com/kubernetes-engine/docs/concepts/about-container-images
		blockLatestTag: true,  // Block :latest tags
	}
}

func NewImagePolicyAgentWithConfig(config ImagePolicyConfig) *ImagePolicyAgent {
	agent := NewImagePolicyAgent()

	if len(config.AllowedRegistries) > 0 {
		agent.allowedRegistries = config.AllowedRegistries
	}
	if len(config.BlockedRegistries) > 0 {
		agent.blockedRegistries = config.BlockedRegistries
	}
	agent.requireDigest = config.RequireDigest
	agent.blockLatestTag = config.BlockLatestTag

	return agent
}

func (i *ImagePolicyAgent) Name() string {
	return i.name
}

// check if the agent can handle the request
func (i *ImagePolicyAgent) CanHandle(req admissionv1.AdmissionRequest) bool {
	// Handle Pod CREATE and UPDATE operations
	return req.Kind.Kind == "Pod" &&
		(req.Operation == admissionv1.Create || req.Operation == admissionv1.Update)
}

// handle the request
func (i *ImagePolicyAgent) Handle(ctx context.Context, req admissionv1.AdmissionRequest) (mesh.AgentDecision, error) {
	// Parse the pod from the request
	pod := &corev1.Pod{}
	if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Failed to parse pod: %v", err),
			Code:    400,
		}, nil
	}

	allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)

	for _, container := range allContainers {
		if decision := i.validateImage(container.Name, container.Image); !decision.Allowed {
			return decision, nil
		}
	}

	// all images passed validation, congrats!
	return mesh.AgentDecision{
		Allowed: true,
		Reason:  "All container images meet policy requirements",
		Code:    200,
	}, nil
}

func (i *ImagePolicyAgent) validateImage(containerName, image string) mesh.AgentDecision {
	if decision := i.checkBlockedRegistries(containerName, image); !decision.Allowed {
		return decision
	}

	if decision := i.checkAllowedRegistries(containerName, image); !decision.Allowed {
		return decision
	}

	if decision := i.checkLatestTag(containerName, image); !decision.Allowed {
		return decision
	}

	if decision := i.checkDigestRequirement(containerName, image); !decision.Allowed {
		return decision
	}

	if decision := i.checkSuspiciousPatterns(containerName, image); !decision.Allowed {
		return decision
	}

	return mesh.AgentDecision{Allowed: true}
}

func (i *ImagePolicyAgent) checkBlockedRegistries(containerName, image string) mesh.AgentDecision {
	for _, blocked := range i.blockedRegistries {
		if strings.HasPrefix(image, blocked) {
			return mesh.AgentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Container %s uses image from blocked registry: %s", containerName, blocked),
				Code:    403,
			}
		}
	}
	return mesh.AgentDecision{Allowed: true}
}

func (i *ImagePolicyAgent) checkAllowedRegistries(containerName, image string) mesh.AgentDecision {
	if len(i.allowedRegistries) == 0 {
		return mesh.AgentDecision{Allowed: true} // No restrictions if no allowed registries configured
	}

	// Normalize image to include docker.io prefix if missing
	normalizedImage := i.normalizeImageName(image)

	for _, allowed := range i.allowedRegistries {
		if strings.HasPrefix(normalizedImage, allowed) {
			return mesh.AgentDecision{Allowed: true}
		}
	}

	return mesh.AgentDecision{
		Allowed: false,
		Reason:  fmt.Sprintf("Container %s uses image from non-allowed registry: %s", containerName, image),
		Code:    403,
	}
}

func (i *ImagePolicyAgent) checkLatestTag(containerName, image string) mesh.AgentDecision {
	if !i.blockLatestTag {
		return mesh.AgentDecision{Allowed: true}
	}

	if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Container %s uses :latest tag or no tag (defaults to :latest): %s", containerName, image),
			Code:    403,
		}
	}

	return mesh.AgentDecision{Allowed: true}
}

func (i *ImagePolicyAgent) checkDigestRequirement(containerName, image string) mesh.AgentDecision {
	if !i.requireDigest {
		return mesh.AgentDecision{Allowed: true}
	}

	if !strings.Contains(image, "@sha256:") {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Container %s must use image digest (sha256) instead of tag: %s", containerName, image),
			Code:    403,
		}
	}

	return mesh.AgentDecision{Allowed: true}
}

// TODO: Find a better way to do this, hardcoded list of suspicious patterns arent efficient
func (i *ImagePolicyAgent) checkSuspiciousPatterns(containerName, image string) mesh.AgentDecision {
	suspiciousPatterns := []string{
		"bitcoin",
		"miner",
		"cryptominer",
		"xmrig",
		"backdoor",
		"malware",
		"trojan",
		"...",
		"../",
	}

	imageLower := strings.ToLower(image)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(imageLower, pattern) {
			return mesh.AgentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Container %s uses suspicious image name pattern '%s': %s", containerName, pattern, image),
				Code:    403,
			}
		}
	}

	return mesh.AgentDecision{Allowed: true}
}

func (i *ImagePolicyAgent) normalizeImageName(image string) string {
	// If image contains a dot or colon followed by a port number, it likely has a registry
	if strings.Contains(image, "/") {
		parts := strings.Split(image, "/")
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			return image // Already has registry
		}
	}

	// If image doesn't start with a registry, assume docker.io
	if !strings.Contains(strings.Split(image, "/")[0], ".") {
		if strings.Contains(image, "/") {
			return "docker.io/" + image
		} else {
			return "docker.io/library/" + image
		}
	}

	return image
}
