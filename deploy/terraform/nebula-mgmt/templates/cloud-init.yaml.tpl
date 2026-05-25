#cloud-config
# nebula-mgmt bootstrap. Pulls a release `.deb`, lays down configs and
# secrets, then runs `nebula-mgmt init` exactly once (the script guards on
# the presence of the CA file).
#
# Re-running this user-data is a no-op once the initial install succeeds.
write_files:
  - path: /etc/nebula-mgmt/server.yml
    permissions: '0640'
    owner: root:nebula-mgmt
    content: |
      listen: ":8080"
      data_dir: "${data_dir}"
      db_path: "${data_dir}/nebula.db"
      log_level: "info"
      tls_cert: "${tls_cert_path}"
      tls_key: "${tls_key_path}"
      allow_self_registration: false
      metrics:
        prometheus: true
  - path: /etc/systemd/system/nebula-mgmt.service.d/override.conf
    permissions: '0644'
    content: |
      [Service]
      EnvironmentFile=/etc/nebula-mgmt/secrets.env
  - path: /etc/nebula-mgmt/secrets.env
    permissions: '0600'
    owner: root:nebula-mgmt
    content: |
      NEBULA_MGMT_MASTER_KEY=${master_key}
      NEBULA_MGMT_CA_PASSPHRASE=${ca_passphrase}

runcmd:
  - |
    set -euo pipefail
    arch=$(dpkg --print-architecture 2>/dev/null || rpm --eval '%{_arch}')
    case "$arch" in
      amd64|x86_64) goarch=amd64 ;;
      arm64|aarch64) goarch=arm64 ;;
      *) echo "unsupported arch: $arch" >&2; exit 1 ;;
    esac

    version="${release_version}"
    if [ "$version" = "latest" ]; then
      version=$(curl -fsSL https://api.github.com/repos/forgekeep/nebula-mesh/releases/latest | sed -n 's/.*"tag_name": *"\(v[^"]*\)".*/\1/p')
    fi

    pkg=$(mktemp --suffix=.deb)
    curl -fsSL -o "$pkg" \
      "https://github.com/forgekeep/nebula-mesh/releases/download/$${version}/nebula-mgmt_$${version#v}_linux_$${goarch}.deb"
    apt-get install -y "$pkg" || (apt-get update && apt-get install -y "$pkg")

    systemctl daemon-reload

    if [ ! -f "${data_dir}/ca.crt" ]; then
      install -d -o nebula-mgmt -g nebula-mgmt -m 0750 "${data_dir}"
      runuser -u nebula-mgmt -- env $(cat /etc/nebula-mgmt/secrets.env) \
        nebula-mgmt init --config /etc/nebula-mgmt/server.yml --admin-username "${admin_username}"
    fi

    systemctl enable --now nebula-mgmt.service
