-- Unsafe networks are the non-overlay prefixes a host is authorized to route
-- for. They ride inside the signed certificate (Nebula's unsafeNetworks), not
-- in the rendered config: a gateway whose cert omits the prefix silently
-- refuses to route it, and peers drop the traffic in Firewall.Drop before any
-- firewall rule is evaluated. Before this column the server had no way to
-- express the provider half of an unsafe route, so advanced.unsafe_routes on
-- the consumer side could never work end to end (#348).
ALTER TABLE hosts ADD COLUMN unsafe_networks_json TEXT NOT NULL DEFAULT '[]';

-- Certificates already issued carry no unsafe networks, and the column starts
-- empty for every host, so no cert becomes stale here. Hosts that need one get
-- it on the next re-issuance triggered by the operator setting the field.
