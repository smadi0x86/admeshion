package agents

import (
	"context"
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/admeshion/admission-mesh/pkg/mesh"
)

type PodSecurityAgent struct {
	name string
}

func NewPodSecurityAgent() *PodSecurityAgent {
	return &PodSecurityAgent{
		name: "pod-security-agent",
	}
}

func (p *PodSecurityAgent) Name() string {
	return p.name
}

// check if the agent can handle the request
func (p *PodSecurityAgent) CanHandle(req admissionv1.AdmissionRequest) bool {
	// Handle Pod CREATE and UPDATE operations
	return req.Kind.Kind == "Pod" &&
		(req.Operation == admissionv1.Create || req.Operation == admissionv1.Update)
}

// handle the request
func (p *PodSecurityAgent) Handle(ctx context.Context, req admissionv1.AdmissionRequest) (mesh.AgentDecision, error) {
	// Parse the pod from the request
	pod := &corev1.Pod{}
	if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Failed to parse pod: %v", err),
			Code:    400,
		}, nil
	}

	// Apply various security checks
	if decision := p.checkPrivilegedContainers(pod); !decision.Allowed {
		return decision, nil
	}

	if decision := p.checkHostPath(pod); !decision.Allowed {
		return decision, nil
	}

	if decision := p.checkHostNetwork(pod); !decision.Allowed {
		return decision, nil
	}

	if decision := p.checkHostPID(pod); !decision.Allowed {
		return decision, nil
	}

	if decision := p.checkHostIPC(pod); !decision.Allowed {
		return decision, nil
	}

	if decision := p.checkCapabilities(pod); !decision.Allowed {
		return decision, nil
	}

	if decision := p.checkRunAsRoot(pod); !decision.Allowed {
		return decision, nil
	}

	// All checks passed, congrats!
	return mesh.AgentDecision{
		Allowed: true,
		Reason:  "Pod meets security requirements",
		Code:    200,
	}, nil
}

// checkPrivilegedContainers ensures no containers run in privileged mode
func (p *PodSecurityAgent) checkPrivilegedContainers(pod *corev1.Pod) mesh.AgentDecision {
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return mesh.AgentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Container %s runs in privileged mode", container.Name),
				Code:    403,
			}
		}
	}

	for _, container := range pod.Spec.InitContainers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			return mesh.AgentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Init container %s runs in privileged mode", container.Name),
				Code:    403,
			}
		}
	}

	return mesh.AgentDecision{Allowed: true}
}

// checkHostPath ensures no hostPath volumes are used
func (p *PodSecurityAgent) checkHostPath(pod *corev1.Pod) mesh.AgentDecision {
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			return mesh.AgentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Volume %s uses hostPath which is not allowed", volume.Name),
				Code:    403,
			}
		}
	}
	return mesh.AgentDecision{Allowed: true}
}

// checkHostNetwork ensures pod doesn't use host network
func (p *PodSecurityAgent) checkHostNetwork(pod *corev1.Pod) mesh.AgentDecision {
	if pod.Spec.HostNetwork {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  "Pod uses host network which is not allowed",
			Code:    403,
		}
	}
	return mesh.AgentDecision{Allowed: true}
}

// checkHostPID ensures pod doesn't use host PID namespace
func (p *PodSecurityAgent) checkHostPID(pod *corev1.Pod) mesh.AgentDecision {
	if pod.Spec.HostPID {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  "Pod uses host PID namespace which is not allowed",
			Code:    403,
		}
	}
	return mesh.AgentDecision{Allowed: true}
}

// checkHostIPC ensures pod doesn't use host IPC namespace
func (p *PodSecurityAgent) checkHostIPC(pod *corev1.Pod) mesh.AgentDecision {
	if pod.Spec.HostIPC {
		return mesh.AgentDecision{
			Allowed: false,
			Reason:  "Pod uses host IPC namespace which is not allowed",
			Code:    403,
		}
	}
	return mesh.AgentDecision{Allowed: true}
}

// checkCapabilities ensures no dangerous capabilities are added
func (p *PodSecurityAgent) checkCapabilities(pod *corev1.Pod) mesh.AgentDecision {
	dangerousCapabilities := []string{
		"SYS_ADMIN",
		"NET_ADMIN",
		"SYS_TIME",
		"SYS_MODULE",
		"DAC_READ_SEARCH",
		"DAC_OVERRIDE",
	}

	allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)

	for _, container := range allContainers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Capabilities != nil &&
			container.SecurityContext.Capabilities.Add != nil {

			for _, cap := range container.SecurityContext.Capabilities.Add {
				for _, dangerous := range dangerousCapabilities {
					if string(cap) == dangerous {
						return mesh.AgentDecision{
							Allowed: false,
							Reason:  fmt.Sprintf("Container %s adds dangerous capability %s", container.Name, cap),
							Code:    403,
						}
					}
				}
			}
		}
	}
	return mesh.AgentDecision{Allowed: true}
}

// checkRunAsRoot ensures containers don't run as root
func (p *PodSecurityAgent) checkRunAsRoot(pod *corev1.Pod) mesh.AgentDecision {
	allContainers := append(pod.Spec.Containers, pod.Spec.InitContainers...)

	for _, container := range allContainers {
		// Check container-level security context
		if container.SecurityContext != nil &&
			container.SecurityContext.RunAsUser != nil &&
			*container.SecurityContext.RunAsUser == 0 {
			return mesh.AgentDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Container %s runs as root (uid 0)", container.Name),
				Code:    403,
			}
		}

		// If no container-level setting, check pod-level
		if container.SecurityContext == nil || container.SecurityContext.RunAsUser == nil {
			if pod.Spec.SecurityContext != nil &&
				pod.Spec.SecurityContext.RunAsUser != nil &&
				*pod.Spec.SecurityContext.RunAsUser == 0 {
				return mesh.AgentDecision{
					Allowed: false,
					Reason:  fmt.Sprintf("Container %s inherits root user from pod security context", container.Name),
					Code:    403,
				}
			}
		}
	}
	return mesh.AgentDecision{Allowed: true}
}
