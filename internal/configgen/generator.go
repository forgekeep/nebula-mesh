package configgen

import (
	"bytes"
	"fmt"
	"text/template"
)

// LighthouseInfo describes a lighthouse node for config generation.
type LighthouseInfo struct {
	NebulaIP   string
	PublicAddr string // "1.2.3.4:4242"
}

// FirewallRule represents a single firewall rule.
type FirewallRule struct {
	Port  string // "any", "22", "443"
	Proto string // "any", "tcp", "udp", "icmp"
	Group string // "any", "admin", etc.
}

// AdvancedUnsafeRoute mirrors models.UnsafeRoute for the template.
type AdvancedUnsafeRoute struct {
	Route string
	Via   string
}

// GeneratorInput contains all parameters needed to generate a Nebula config.
type GeneratorInput struct {
	HostName         string
	NebulaIP         string
	IsLighthouse     bool
	IsRelay          bool
	CACertPath       string
	CertPath         string
	KeyPath          string
	ListenPort       int
	Lighthouses      []LighthouseInfo
	Relays           []string
	FirewallInbound  []FirewallRule
	FirewallOutbound []FirewallRule

	// Optional per-host overrides. Zero values mean "use the default".
	PunchyOverride   *bool
	ListenHost       string
	MTU              int
	TunDevice        string
	UnsafeRoutes     []AdvancedUnsafeRoute
}

const configTemplate = `pki:
  ca: {{ .CACertPath }}
  cert: {{ .CertPath }}
  key: {{ .KeyPath }}

{{- if .IsLighthouse }}

static_host_map: {}

lighthouse:
  am_lighthouse: true
  {{- if gt .ListenPort 0 }}
  # Lighthouse listens on port {{ .ListenPort }}
  {{- end }}

listen:
  host: {{ if .ListenHost }}{{ .ListenHost }}{{ else }}0.0.0.0{{ end }}
  port: {{ if gt .ListenPort 0 }}{{ .ListenPort }}{{ else }}4242{{ end }}

{{- else }}

static_host_map:
  {{- range .Lighthouses }}
  "{{ .NebulaIP }}": ["{{ .PublicAddr }}"]
  {{- end }}

lighthouse:
  am_lighthouse: false
  hosts:
    {{- range .Lighthouses }}
    - "{{ .NebulaIP }}"
    {{- end }}

listen:
  host: {{ if .ListenHost }}{{ .ListenHost }}{{ else }}0.0.0.0{{ end }}
  port: {{ if gt .ListenPort 0 }}{{ .ListenPort }}{{ else }}0{{ end }}

{{- end }}

punchy:
  punch: {{ if .PunchyOverride }}{{ .PunchyOverride }}{{ else }}true{{ end }}
{{- if or .MTU .TunDevice .UnsafeRoutes }}

tun:
  {{- if .TunDevice }}
  dev: {{ .TunDevice }}
  {{- end }}
  {{- if .MTU }}
  mtu: {{ .MTU }}
  {{- end }}
  {{- if .UnsafeRoutes }}
  unsafe_routes:
    {{- range .UnsafeRoutes }}
    - route: {{ .Route }}
      via: {{ .Via }}
    {{- end }}
  {{- end }}
{{- end }}

{{- if .IsRelay }}

relay:
  am_relay: true
{{- else if .Relays }}

relay:
  relays:
    {{- range .Relays }}
    - "{{ . }}"
    {{- end }}
{{- end }}

logging:
  level: info
  format: text

firewall:
  outbound:
    {{- range .FirewallOutbound }}
    - port: {{ .Port }}
      proto: {{ .Proto }}
      {{- if ne .Group "any" }}
      group: {{ .Group }}
      {{- else }}
      host: any
      {{- end }}
    {{- end }}

  inbound:
    {{- range .FirewallInbound }}
    - port: {{ .Port }}
      proto: {{ .Proto }}
      {{- if ne .Group "any" }}
      group: {{ .Group }}
      {{- else }}
      host: any
      {{- end }}
    {{- end }}
`

// Generate produces a Nebula config.yml from the given input.
func Generate(input GeneratorInput) ([]byte, error) {
	tmpl, err := template.New("nebula-config").Parse(configTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, input); err != nil {
		return nil, fmt.Errorf("execute template: %w", err)
	}

	return buf.Bytes(), nil
}
