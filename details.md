# Nebula Management Platform — Детальный план реализации

## Обзор

Self-hosted платформа для полного управления Nebula mesh-сетью. Два основных компонента: management server (`nebula-mgmt`) и agent (`nebula-agent`). Go монорепо, single module.

## Структура репозитория

```
nebula-mgmt/
├── go.mod                          # github.com/juev/nebula-mesh
├── go.sum
├── .gitignore
├── .golangci.yml                   # Linter configuration
├── Makefile                        # Build targets
├── README.md
├── nebula-research.md              # Результаты исследования
│
├── cmd/
│   ├── nebula-mgmt/                # Management server binary
│   │   └── main.go
│   └── nebula-agent/               # Agent binary
│       └── main.go
│
├── internal/
│   ├── config/                     # Конфигурация server и agent
│   │   ├── server.go               # ServerConfig struct + parse
│   │   ├── server_test.go
│   │   ├── agent.go                # AgentConfig struct + parse
│   │   └── agent_test.go
│   │
│   ├── pki/                        # PKI operations (обёртка над nebula/cert)
│   │   ├── ca.go                   # CA creation, load, save
│   │   ├── ca_test.go
│   │   ├─�� signer.go               # Certificate signing
│   │   ├── signer_test.go
│   │   ├── blocklist.go            # Blocklist management
│   │   └── blocklist_test.go
│   │
│   ��── store/                      # Database layer
│   │   ├── store.go                # Store interface
│   │   ├── sqlite.go               # SQLite implementation
│   │   ├── sqlite_test.go
│   │   ├── hosts.go                # Host CRUD
│   │   ├── hosts_test.go
│   │   ├── tokens.go               # Enrollment tokens
│   │   ├── tokens_test.go
│   │   ├── networks.go             # Network settings
│   │   ├── networks_test.go
│   │   └── migrations/
│   │       ├── embed.go            # go:embed migrations
│   │       ├── 001_initial.up.sql
│   │       └── 001_initial.down.sql
│   │
│   ├── configgen/                  # Nebula config.yml generator
│   │   ├── generator.go            # Template-based config generation
│   │   ├── generator_test.go
│   │   └── templates/
│   │       ├── lighthouse.yml.tmpl
│   │       ├── host.yml.tmpl
│   │       └── relay.yml.tmpl
│   │
│   ├── api/                        # REST API (server)
│   │   ├── server.go               # HTTP server setup, chi router
│   │   ├── middleware.go            # Auth, logging, recovery
│   │   ├── middleware_test.go
│   │   ├── hosts.go                # Host management endpoints
│   │   ├── hosts_test.go
��   │   ├── enroll.go               # Enrollment endpoint
│   │   ├── enroll_test.go
│   │   ├── updates.go              # Agent poll endpoint
│   │   ├── updates_test.go
│   │   ├── networks.go             # Network management endpoints
│   │   └── networks_test.go
│   │
│   ├── agent/                      # Agent logic
│   │   ├���─ enroll.go               # Enrollment flow
│   │   ├── enroll_test.go
│   │   ├── poller.go               # Poll loop + apply updates
│   │   ├── poller_test.go
│   │   ├── nebula.go               # Nebula process management (SIGHUP, status)
│   │   └���─ nebula_test.go
│   │
│   ├── cli/                        # CLI commands (server)
│   │   ├── init.go                 # nebula-mgmt init
│   │   ├── serve.go                # nebula-mgmt serve
│   │   ├── host.go                 # nebula-mgmt host create/list/delete
│   │   └── network.go              # nebula-mgmt network create/list
│   │
│   └── models/                     # Shared domain models
│       ├── host.go                 # Host, HostStatus
│       ├─��� network.go              # Network, CIDR settings
│       ├── token.go                # EnrollmentToken
│       └── certificate.go          # CertificateInfo (metadata, not key material)
│
├── tests/
│   └── integration/
│       └── e2e_test.go             # End-to-end: server + agent
│
└── configs/
    ├── server.example.yml          # Example server config
    └── agent.example.yml           # Example agent config
```

## Зависимости

```
github.com/slackhq/nebula           # PKI library (cert package)
github.com/go-chi/chi/v5            # HTTP router
modernc.org/sqlite                   # Pure Go SQLite driver
gopkg.in/yaml.v3                     # YAML parsing (Nebula config compat)
github.com/google/uuid               # Token generation
```

Без CGO. Pure Go для кросс-компиляции (Linux, macOS, Windows).

## Database Schema (SQLite)

```sql
-- 001_initial.up.sql

CREATE TABLE networks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    cidr        TEXT NOT NULL,           -- e.g., "192.168.100.0/24"
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE hosts (
    id          TEXT PRIMARY KEY,
    network_id  TEXT NOT NULL REFERENCES networks(id),
    name        TEXT NOT NULL,
    nebula_ip   TEXT NOT NULL,           -- e.g., "192.168.100.5"
    groups      TEXT NOT NULL DEFAULT '[]', -- JSON array
    role        TEXT NOT NULL DEFAULT 'host', -- host, lighthouse, relay
    is_lighthouse BOOLEAN NOT NULL DEFAULT 0,
    is_relay    BOOLEAN NOT NULL DEFAULT 0,
    public_ip   TEXT,                    -- for lighthouse/relay
    listen_port INTEGER DEFAULT 4242,    -- for lighthouse/relay
    status      TEXT NOT NULL DEFAULT 'pending', -- pending, enrolled, blocked
    cert_fingerprint TEXT,               -- current cert fingerprint
    cert_expires_at  DATETIME,
    last_seen_at     DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(network_id, name),
    UNIQUE(network_id, nebula_ip)
);

CREATE TABLE enrollment_tokens (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    token       TEXT NOT NULL UNIQUE,
    used        BOOLEAN NOT NULL DEFAULT 0,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE certificates (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    fingerprint     TEXT NOT NULL UNIQUE,
    pem             TEXT NOT NULL,        -- PEM-encoded certificate (no private key)
    not_before      DATETIME NOT NULL,
    not_after       DATETIME NOT NULL,
    is_current      BOOLEAN NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocklist (
    fingerprint TEXT PRIMARY KEY,
    host_id     TEXT REFERENCES hosts(id),
    reason      TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE network_config (
    network_id      TEXT NOT NULL REFERENCES networks(id),
    key             TEXT NOT NULL,       -- e.g., "firewall.inbound", "lighthouse.dns"
    value           TEXT NOT NULL,       -- JSON value
    PRIMARY KEY (network_id, key)
);
```

## API Endpoints

### Management API (требует Bearer token)

```
POST   /api/v1/networks                   # Создать сеть
GET    /api/v1/networks                   # Список сетей
GET    /api/v1/networks/{id}              # Получить сеть

POST   /api/v1/hosts                      # Создать хост → возвращает enrollment token
GET    /api/v1/hosts                      # Список хостов (фильтр по network, group, status)
GET    /api/v1/hosts/{id}                 # Получить хост
DELETE /api/v1/hosts/{id}                 # Удалить хост (добавить cert в blocklist)
POST   /api/v1/hosts/{id}/block           # Заблокировать хост
POST   /api/v1/hosts/{id}/renew           # Принудительное обновление сертификата

GET    /api/v1/blocklist                  # Текущий blocklist

GET    /health                            # Health check
```

### Agent API (без Bearer token)

```
POST   /api/v1/enroll                     # Enrollment: token + public key → cert + config
GET    /api/v1/agent/updates?fingerprint=X # Poll: получить обновления
POST   /api/v1/agent/status               # Report: статус агента (optional)
```

### Enrollment Request/Response

```json
// POST /api/v1/enroll
// Request:
{
  "token": "tok_abc123...",
  "public_key_pem": "-----BEGIN NEBULA X25519 PUBLIC KEY-----\n..."
}

// Response (200 OK):
{
  "certificate_pem": "-----BEGIN NEBULA CERTIFICATE-----\n...",
  "ca_certificate_pem": "-----BEGIN NEBULA CERTIFICATE-----\n...",
  "config_yaml": "pki:\n  ca: /etc/nebula/ca.crt\n..."
}
```

### Agent Updates Request/Response

```json
// GET /api/v1/agent/updates?fingerprint=abc123
// Response (200 OK, есть обновления):
{
  "has_updates": true,
  "certificate_pem": "-----BEGIN NEBULA CERTIFICATE-----\n...",  // null if not changed
  "ca_certificate_pem": "-----BEGIN NEBULA CERTIFICATE-----\n...", // null if not changed
  "config_yaml": "...",     // null if not changed
  "blocklist": ["fingerprint1", "fingerprint2"]  // full current blocklist
}

// Response (304 Not Modified, нет обновлений):
// Empty body
```

---

## Phase 1: MVP — Детальный план

Цель: рабочий сервер + агент, позволяющие создать сеть, добавить хосты через enrollment, и управлять ими через CLI + API.

### 1.1 Инициализация проекта

**Что делаем:**
- `go mod init github.com/juev/nebula-mesh`
- Минимальные `main.go` для обоих бинарников (пустые, но компилируемые)
- `.gitignore` (бинарники, SQLite files, `*.key`, `.env`)
- `.golangci.yml` (golangci-lint config)
- `Makefile` с target'ами: `build`, `test`, `lint`, `all`

**Критерий готовности:** `make all` проходит без ошибок.

### 1.2 Конфигурация

**Server config (`configs/server.example.yml`):**
```yaml
listen: ":8080"
data_dir: "/var/lib/nebula-mgmt"
db_path: "/var/lib/nebula-mgmt/nebula.db"
api_key: ""  # generated on init
log_level: "info"
```

**Agent config (`configs/agent.example.yml`):**
```yaml
server_url: "https://mgmt.example.com:8080"
data_dir: "/etc/nebula"
poll_interval: "30s"
nebula_config_path: "/etc/nebula/config.yml"
nebula_pid_file: "/run/nebula.pid"
```

**Реализация:**
- `internal/config/server.go` — `ServerConfig` struct, `LoadServerConfig(path) (*ServerConfig, error)`
- `internal/config/agent.go` — `AgentConfig` struct, `LoadAgentConfig(path) (*AgentConfig, error)`
- Defaults для всех полей, валидация при загрузке

### 1.3 PKI Engine

Обёртка над `nebula/cert` с persistence.

**`internal/pki/ca.go`:**
```go
type CAManager struct {
    caCert cert.Certificate
    caKey  []byte // decrypted private key in memory
}

func NewCA(name string, duration time.Duration) (*CAManager, []byte, error)
// Returns: manager + encrypted PEM of CA key (for backup display)

func LoadCA(certPEM, encryptedKeyPEM, passphrase []byte) (*CAManager, error)

func (m *CAManager) CACertPEM() []byte
func (m *CAManager) CACertFingerprint() string
```

**`internal/pki/signer.go`:**
```go
type SignRequest struct {
    Name       string
    PublicKey  []byte
    Networks   []netip.Prefix
    Groups     []string
    Duration   time.Duration
}

func (m *CAManager) Sign(req SignRequest) (cert.Certificate, error)
```

**`internal/pki/blocklist.go`:**
```go
type Blocklist struct {
    mu           sync.RWMutex
    fingerprints map[string]struct{}
}

func NewBlocklist() *Blocklist
func (b *Blocklist) Add(fingerprint string)
func (b *Blocklist) Remove(fingerprint string)
func (b *Blocklist) Contains(fingerprint string) bool
func (b *Blocklist) List() []string
```

### 1.4 Storage Layer

**`internal/store/store.go` — interface:**
```go
type Store interface {
    // Networks
    CreateNetwork(ctx context.Context, n *models.Network) error
    GetNetwork(ctx context.Context, id string) (*models.Network, error)
    ListNetworks(ctx context.Context) ([]*models.Network, error)

    // Hosts
    CreateHost(ctx context.Context, h *models.Host) error
    GetHost(ctx context.Context, id string) (*models.Host, error)
    GetHostByFingerprint(ctx context.Context, fingerprint string) (*models.Host, error)
    ListHosts(ctx context.Context, filter HostFilter) ([]*models.Host, error)
    UpdateHost(ctx context.Context, h *models.Host) error
    DeleteHost(ctx context.Context, id string) error

    // Enrollment tokens
    CreateToken(ctx context.Context, t *models.EnrollmentToken) error
    ConsumeToken(ctx context.Context, token string) (*models.EnrollmentToken, error)
    // ConsumeToken: returns token if valid and not used, marks as used atomically

    // Certificates
    SaveCertificate(ctx context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error
    GetCurrentCertificate(ctx context.Context, hostID string) ([]byte, error)

    // Blocklist
    AddToBlocklist(ctx context.Context, fingerprint, hostID, reason string) error
    RemoveFromBlocklist(ctx context.Context, fingerprint string) error
    GetBlocklist(ctx context.Context) ([]string, error)

    // Migrations
    Migrate(ctx context.Context) error
    Close() error
}
```

**`internal/store/sqlite.go`** — SQLite реализация через `modernc.org/sqlite` + `database/sql`.
Миграции embedded через `go:embed`.

### 1.5 Config Generator

**`internal/configgen/generator.go`:**
```go
type GeneratorInput struct {
    Host       *models.Host
    Network    *models.Network
    CACertPath string
    CertPath   string
    KeyPath    string
    Lighthouses []LighthouseInfo  // IP → public address mapping
    FirewallRules []FirewallRule
}

type LighthouseInfo struct {
    NebulaIP  string
    PublicAddr string // "1.2.3.4:4242"
}

func Generate(input GeneratorInput) ([]byte, error) // returns YAML
```

Go `text/template` с YAML output. Шаблоны embedded через `go:embed`.

### 1.6 REST API

Chi router с middleware chain:
1. `RequestID` — уникальный ID запроса
2. `Logger` — structured logging через `slog`
3. `Recoverer` — panic recovery
4. `BearerAuth` — проверка API key (только для management endpoints)

**Enrollment endpoint** (`POST /api/v1/enroll`):
1. Parse token из request body
2. `store.ConsumeToken()` — валидация + инвалидация в одной транзакции
3. Parse public key PEM из request body
4. `pki.Sign()` — подписание сертификата
5. `configgen.Generate()` — генерация config.yml
6. `store.SaveCertificate()` — сохранение cert metadata
7. `store.UpdateHost()` — status = "enrolled"
8. Return: cert PEM + CA cert PEM + config YAML

**Agent updates endpoint** (`GET /api/v1/agent/updates?fingerprint=X`):
1. `store.GetHostByFingerprint()` — найти хост
2. Проверить: cert renewed? config changed? blocklist changed?
3. Если нет изменений → 304
4. Если есть → 200 с обновлёнными данными

### 1.7 Agent

**Enrollment flow** (`internal/agent/enroll.go`):
1. Генерировать X25519 keypair (`crypto/rand`)
2. `POST /api/v1/enroll` с token + public key PEM
3. Сохранить: `ca.crt`, `host.crt`, `host.key`, `config.yml` в data_dir
4. Permissions: `0600` для ключей, `0644` для сертификатов

**Poll loop** (`internal/agent/poller.go`):
1. Каждые N секунд: `GET /api/v1/agent/updates?fingerprint=<current>`
2. При 304 → sleep
3. При 200 → обновить файлы, отправить SIGHUP Nebula (через PID file или `pkill -HUP nebula`)
4. При ошибке → логировать, retry с backoff

**CLI:**
- `nebula-agent --server=<URL> --token=<TOKEN> [--config=<path>] [--data-dir=<dir>]` — первый запуск: enroll, запись `agent.yml` (0600), старт поллера
- `nebula-agent [--config=<path>]` — последующие запуски (token не нужен)
- `nebula-agent --update-config --server=<URL>` — атомарно переписать поле в `agent.yml`
- Legacy (deprecated, поддерживается один релиз): `nebula-agent enroll …` / `nebula-agent run …`

### 1.8 Server CLI

- `nebula-mgmt init [--config=<path>]` — создать CA, сгенерировать API key, инициализировать DB
- `nebula-mgmt serve [--config=<path>]` — запустить HTTP server
- `nebula-mgmt host create --name=<name> --ip=<nebula-ip> --network=<id> [--groups=<g1,g2>] [--lighthouse] [--public-ip=<ip>]`
- `nebula-mgmt host list [--network=<id>]`
- `nebula-mgmt host delete --id=<id>`
- `nebula-mgmt network create --name=<name> --cidr=<cidr>`
- `nebula-mgmt network list`

### 1.9 Integration Test

E2E test без внешних зависимостей:
1. `init` — создать CA + DB in-memory
2. `network create` — создать тестовую сеть
3. `host create` — создать lighthouse + host → получить tokens
4. Start HTTP server in-process
5. Agent enrollment — отправить token, получить cert
6. Agent poll — проверить 304 (нет обновлений)
7. Block host — добавить в blocklist
8. Agent poll — проверить что blocklist обновлён
9. Verify: все сертификаты валидны, config.yml корректен

---

## Phase 2: Web UI + Auto-renewal + Lighthouse Management

Цель: веб-интерфейс для администрирования, автоматическое обновление сертификатов, полное управление lighthouse и relay.

### 2.1 Web UI

**Tech stack:** Svelte (или React) SPA, embedded в Go binary через `go:embed`.

**Страницы:**
- Dashboard: обзор сети (хосты, статусы, expiring certs)
- Networks: список сетей, создание новой
- Hosts: список хостов с фильтрами, создание, enrollment code display
- Host detail: статус, сертификат, группы, firewall rules
- Lighthouses: список lighthouse с статусом, добавление нового
- Blocklist: управление заблокированными сертификатами
- Settings: API keys, CA info, server config

**API расширение:**
```
GET    /api/v1/dashboard/stats            # Статистика для dashboard
GET    /api/v1/hosts/{id}/certificate     # Детали сертификата хоста
POST   /api/v1/api-keys                   # Создать API key
DELETE /api/v1/api-keys/{id}              # Удалить API key
```

**Аутентификация UI:** session-based (cookie) с login form. Отдельно от API key auth.

### 2.2 Auto-renewal

**Серверная часть:**
- Background goroutine проверяет сертификаты каждый час
- Сертификаты с оставшимся TTL < 20% помечаются для обновления
- При следующем poll агент получает новый сертификат

**Агентная часть:**
- При получении нового сертификата: записать файлы, SIGHUP Nebula
- Логирование: "certificate renewed, expires at <date>"

**CA rotation support:**
- API endpoint `POST /api/v1/ca/rotate` — начать ротацию CA
- Server генерирует новый intermediate CA
- Переходный период: оба CA в `pki.ca` на всех хостах
- Постепенный перевыпуск: каждый хост при следующем renewal получает cert от нового CA
- После перевыпуска всех → удаление старого CA

### 2.3 Lighthouse Management

**Host creation с ролью lighthouse:**
```
POST /api/v1/hosts
{
  "name": "lighthouse-eu",
  "role": "lighthouse",
  "public_ip": "203.0.113.10",
  "listen_port": 4242,
  "nebula_ip": "192.168.100.1",
  "network_id": "net_xxx"
}
```

**Автоматическое обновление конфигураций:**
При добавлении/удалении lighthouse → все хосты сети получают обновлённый `config.yml` с новым `static_host_map` и `lighthouse.hosts` при следующем poll.

**Relay management:** аналогично lighthouse, с `role: "relay"` и соответствующим `relay.am_relay: true` в config template.

**Lighthouse DNS:**
- Опция в network config: `lighthouse_dns: true`
- При включении: lighthouse config получает `lighthouse.serve_dns: true`

**Мониторинг lighthouse:**
- Agent на lighthouse отправляет extended status: active tunnels, handshake stats
- Dashboard показывает health status lighthouse

### 2.4 Firewall Rules Management

**API:**
```
GET    /api/v1/networks/{id}/firewall     # Текущие правила
PUT    /api/v1/networks/{id}/firewall     # Обновить правила
```

**Model:**
```json
{
  "inbound": [
    {"port": "any", "proto": "icmp", "groups": ["any"]},
    {"port": "22", "proto": "tcp", "groups": ["admin"]}
  ],
  "outbound": [
    {"port": "any", "proto": "any", "groups": ["any"]}
  ]
}
```

При обновлении правил → все хосты сети получают новый config при poll.

### 2.5 Network management расширения

- **IP allocation:** автоматическое назначение следующего свободного IP при создании хоста (опционально, можно указать вручную)
- **Groups management:** CRUD для групп с привязкой к firewall rules
- **Network settings:** MTU, punchy, cipher, relay defaults

### 2.6 Audit Log

Каждое действие через API логируется:
```sql
CREATE TABLE audit_log (
    id         TEXT PRIMARY KEY,
    timestamp  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor      TEXT NOT NULL,      -- API key ID or "system"
    action     TEXT NOT NULL,      -- "host.create", "host.block", "cert.renew"
    resource   TEXT NOT NULL,      -- host ID, network ID, etc.
    details    TEXT                 -- JSON with details
);
```

API: `GET /api/v1/audit-log?from=<date>&to=<date>&action=<action>`

---

## Будущие фазы (не планируем детально)

### Phase 3: Mobile + QR Enrollment
- Форк Mobile Nebula с pull-агентом
- QR-code enrollment (encode token + server URL)
- Deep link support

### Phase 4: Enterprise
- OIDC/SSO authentication для Web UI
- RBAC — роли администраторов (viewer, operator, admin)
- Multi-user support
- PostgreSQL support

### Phase 5: Advanced PKI
- PKCS#11/HSM support для CA key
- HashiCorp Vault integration
- Intermediate CA hierarchy (root offline + intermediate online)
- Certificate transparency log

### Phase 6: Monitoring & Observability
- Prometheus metrics endpoint
- Host connectivity graph
- Certificate expiration alerts
- Lighthouse health monitoring dashboard
- Webhook notifications (Slack, Telegram)
