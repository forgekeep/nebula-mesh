package configgen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_MobileProfile(t *testing.T) {
	t.Parallel()

	in := mobileGeneratorInput()
	c := loadGenerated(t, in)

	assert.Equal(t, 10, c.GetInt("handshakes.retries", 0))
	assert.Equal(t, 100*time.Millisecond, c.GetDuration("handshakes.try_interval", 0))
	assert.Equal(t, 60, c.GetInt("lighthouse.interval", 0))
	assert.Equal(t, "[::]", c.GetString("listen.host", ""))
	assert.Equal(t, 0, c.GetInt("listen.port", -1))
	assert.True(t, c.GetBool("punchy.punch", false))
	assert.True(t, c.IsSet("punchy.respond"))
	assert.False(t, c.GetBool("punchy.respond", true))
	assert.Equal(t, "nebula1", c.GetString("tun.dev", ""))
	assert.Equal(t, 1300, c.GetInt("tun.mtu", 0))
	assert.True(t, c.GetBool("tun.drop_local_broadcast", false))
	assert.True(t, c.GetBool("tun.drop_multicast", false))
	assert.True(t, c.GetBool("tunnels.drop_inactive", false))
	assert.Equal(t, 10*time.Minute, c.GetDuration("tunnels.inactivity_timeout", 0))
	assert.True(t, c.IsSet("relay.am_relay"))
	assert.False(t, c.GetBool("relay.am_relay", true))
	assert.True(t, c.GetBool("relay.use_relays", false))
	assert.Equal(t, "drop", c.GetString("firewall.inbound_action", ""))
	assert.Equal(t, "drop", c.GetString("firewall.outbound_action", ""))

	assert.Equal(t, map[string]any{
		"docker.*":   false,
		"nebula1":    false,
		"podman.*":   false,
		"tailscale0": false,
		"tun.*":      false,
		"utun.*":     false,
		"veth.*":     false,
	}, c.GetMap("lighthouse.local_allow_list.interfaces", nil))

	assert.Equal(t, map[string]any{
		"0.0.0.0/0":      true,
		"::/0":           true,
		"127.0.0.0/8":    false,
		"::1/128":        false,
		"169.254.0.0/16": false,
		"fe80::/10":      false,
	}, c.GetMap("lighthouse.remote_allow_list", nil))

	require.Equal(t, []string{"10.0.0.53", "2001:db8::53"}, c.GetStringSlice("mobile_nebula.dns_resolvers", nil))
	require.Equal(t, []string{}, c.GetStringSlice("mobile_nebula.match_domains", nil))
}

func TestGenerate_MobileProfileRejectsPrivateDiscoveryAddresses(t *testing.T) {
	t.Parallel()

	in := mobileGeneratorInput()
	in.Mobile.AllowPrivateRemotes = false
	c := loadGenerated(t, in)

	remoteAllowList := c.GetMap("lighthouse.remote_allow_list", nil)
	for _, cidr := range []string{
		"10.0.0.0/8",
		"100.64.0.0/10",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	} {
		assert.Equal(t, false, remoteAllowList[cidr], cidr)
	}
	assert.Len(t, remoteAllowList, 11)
}

func TestGenerate_MobileProfileOmitsDNSWithoutResolvers(t *testing.T) {
	t.Parallel()

	in := mobileGeneratorInput()
	in.Mobile.DNSResolvers = nil
	in.Mobile.MatchDomains = []string{"corp.example"}
	c := loadGenerated(t, in)

	assert.False(t, c.IsSet("mobile_nebula"))
}

func TestGenerate_MobileProfileUsesAdvancedTunOverrides(t *testing.T) {
	t.Parallel()

	in := mobileGeneratorInput()
	in.TunDevice = "mobile0"
	in.MTU = 1280
	c := loadGenerated(t, in)

	assert.Equal(t, "mobile0", c.GetString("tun.dev", ""))
	assert.Equal(t, 1280, c.GetInt("tun.mtu", 0))
}

func TestGenerate_AgentProfileOmitsMobileSections(t *testing.T) {
	t.Parallel()

	c := loadGenerated(t, GeneratorInput{
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
	})

	assert.Equal(t, "0.0.0.0", c.GetString("listen.host", ""))
	for _, key := range []string{
		"handshakes",
		"tunnels",
		"mobile_nebula",
		"lighthouse.interval",
		"lighthouse.local_allow_list",
		"lighthouse.remote_allow_list",
		"punchy.respond",
		"firewall.inbound_action",
		"firewall.outbound_action",
	} {
		assert.False(t, c.IsSet(key), key)
	}
}

func mobileGeneratorInput() GeneratorInput {
	return GeneratorInput{
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		Relays:     []string{"10.0.0.2"},
		Mobile: &MobileProfile{
			DNSResolvers:        []string{"10.0.0.53", "2001:db8::53"},
			MatchDomains:        []string{},
			AllowPrivateRemotes: true,
		},
	}
}
