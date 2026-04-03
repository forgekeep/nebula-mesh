# Self-hosted управление Nebula mesh: исследование и архитектура решения

## Введение

Nebula — overlay-сеть от Slack (ныне поддерживается Defined Networking), построенная на Noise Protocol Framework с PKI-моделью безопасности[^1]. В отличие от централизованных VPN, узлы устанавливают прямые peer-to-peer туннели, а lighthouse-серверы служат лишь точками обнаружения[^2]. Defined Networking предлагает managed-сервис поверх open-source Nebula — с веб-интерфейсом, автоматическим управлением сертификатами и API[^3]. Однако для self-hosted развёртываний аналогичного решения не существует: экосистема фрагментирована между CLI-утилитами, ранними прототипами и заброшенными проектами.

Данное исследование анализирует архитектуру Defined Networking, существующие open-source решения, механизмы управления PKI и мобильными устройствами — с целью спроектировать self-hosted платформу для полного управления Nebula mesh.

## Архитектура Defined Networking

### Компоненты и взаимодействие

Managed Nebula от Defined Networking состоит из трёх ключевых слоёв[^3][^4]:

1. **Control Plane (admin.defined.net)** — веб-интерфейс и REST API для управления сетями, хостами, ролями и firewall-правилами
2. **DNClient** — агент на каждом хосте, опрашивающий backend каждые ~60 секунд для получения обновлений конфигурации, сертификатов и blocklist[^5]
3. **Data Plane (Nebula)** — open-source ядро, обеспечивающее mesh-связность

> "DNClient is the required client software that allows hosts to join Managed Nebula networks and receive centralized management through the admin panel"[^5].

### Enrollment flow

Процесс подключения нового хоста[^4][^6]:

1. Администратор создаёт хост в панели управления (назначает роль, сеть)
2. Генерируется одноразовый enrollment code
3. На целевой машине устанавливается DNClient
4. DNClient активируется с enrollment code
5. Backend генерирует сертификат и конфигурацию
6. DNClient получает сертификат, ключ и config — запускает Nebula
7. Хост регистрируется на lighthouse и становится доступен в mesh

Для автоматизации доступен API-endpoint `POST /v1/host-and-enrollment-code`, возвращающий enrollment code программно[^6]. Аутентификация — Bearer token с гранулярными scope (`hosts:create`, `hosts:enroll`, `roles:*`)[^7].

### Модель обновлений

DNClient использует **pull-модель**: опрашивает backend каждые ~60 секунд[^5]. Это означает, что изменения (блокировка хоста, обновление firewall-правил, ротация сертификата) распространяются с задержкой до минуты. Активного push нет — только REST polling.

### Ключевое ограничение

DNClient — **проприетарный** компонент. Исходный код закрыт, распространяется только в виде бинарников[^5]. Это делает невозможным прямое переиспользование в self-hosted решении. Однако **всё остальное** — Nebula core, PKI, lighthouse, relay — полностью open-source (MIT)[^1].

## Существующие self-hosted решения

### Nebula Tower

Python/React приложение для управления Nebula через веб-интерфейс[^8].

| Параметр | Значение |
|---|---|
| Версия | 0.1.1 (сентябрь 2025) |
| Backend | Python FastAPI + SQLAlchemy + SQLite |
| Frontend | React + MUI Joy UI |
| Клиент | Fyne (Go-based menubar app) |
| Лицензия | AGPL-3.0 |
| Сертификаты | v2 (IPv6), nightly Nebula |

**Архитектурная особенность**: Tower хранит CA, lighthouse и хостовые сертификаты централизованно на сервере[^8]. Это упрощает администрирование, но создаёт единую точку компрометации.

> "This is a very early version of Nebula Tower. If you find the concept helpful, let's collaborate to improve the app"[^8].

**Ограничения**: ранняя стадия, 91 коммит, зависимость от nightly Nebula, Python-backend ограничивает интеграцию с Go-библиотекой Nebula.

### nebula-est (NEST)

Реализация протокола EST (RFC 7030) для автоматизированного enrollment[^9].

**Архитектура** — четыре микросервиса:

- **NEST Service** — TLS-фасад, координирует запросы
- **NEST CA** — подписывает сертификаты через `nebula-cert`
- **NEST Config** — генерирует конфигурации из Dhall-шаблонов
- **NEST Client** — CLI для запроса сертификатов

**Аутентификация**: HMAC-SHA256 от hostname клиента с секретным ключом сервиса[^9]. Транспорт — TLS 1.3 с ECDHE-ECDSA.

**Преимущества**: RFC-стандарт, поддержка re-enrollment и rekey, server-side key generation.

**Ограничения**: написан на Go (плюс), но использует `nebula-cert` binary вместо библиотеки; не обновлялся с 2023; ориентирован на ICS/IIoT; лицензия не указана.

### nebula-manager

Наиболее зрелый CLI-инструмент (v1.1.0, декабрь 2025)[^10]:

- Управление жизненным циклом сертификатов (генерация, отзыв, мониторинг сроков)
- Валидация `config.yml`
- Диагностика связности (ping, latency, iperf3)
- Управление firewall-правилами
- Автообновление Nebula с rollback

**Ограничения**: Bash-скрипт, только Linux (Debian/Ubuntu/RHEL), нет веб-интерфейса, нет enrollment flow.

### Shieldoo Mesh

Позиционировался как full-featured обёртка с SSO и zero-trust[^11]. По состоянию на апрель 2026: **GitHub-репозитории удалены**, сайт предлагает только SaaS ($0.25/час за пользователя). Непригоден для self-hosting.

### Сводная таблица

| Решение | Язык | Интерфейс | CA management | Enrollment | Состояние |
|---|---|---|---|---|---|
| Nebula Tower | Python/React | Web UI | Централизованное | Invite links | Ранняя стадия |
| NEST | Go | REST API + CLI | EST (RFC 7030) | HMAC token | Не обновляется |
| nebula-manager | Bash | CLI | CLI commands | Нет | Активный |
| Shieldoo | — | — | — | — | **Код удалён** |

## Go-библиотека Nebula для работы с сертификатами

Пакет `github.com/slackhq/nebula/cert` предоставляет полный API для программной работы с PKI[^12]. Ключевые типы:

**Certificate (interface)** — основной тип сертификата:

```go
type Certificate interface {
    Version() Version
    Name() string
    Networks() []netip.Prefix      // overlay IP addresses
    UnsafeNetworks() []netip.Prefix
    Groups() []string
    IsCA() bool
    NotBefore() time.Time
    NotAfter() time.Time
    Issuer() string
    PublicKey() []byte
    Signature() []byte
    CheckSignature(signingPublicKey []byte) bool
    Fingerprint() (string, error)
    Expired(t time.Time) bool
    Marshal() ([]byte, error)
    MarshalPEM() ([]byte, error)
    Copy() Certificate
}
```

**TBSCertificate** — структура для создания и подписания:

```go
type TBSCertificate struct {
    Version        Version
    Name           string
    Networks       []netip.Prefix
    Groups         []string
    IsCA           bool
    NotBefore      time.Time
    NotAfter       time.Time
    PublicKey      []byte
    Curve          Curve
}

func (t *TBSCertificate) Sign(signer Certificate, curve Curve, key []byte) (Certificate, error)
func (t *TBSCertificate) SignWith(signer Certificate, curve Curve, sp SignerLambda) (Certificate, error)
```

**CAPool** — пул CA для верификации:

```go
func NewCAPoolFromPEM(caPEMs []byte) (*CAPool, error)
func (ncp *CAPool) VerifyCertificate(now time.Time, c Certificate) (*CachedCertificate, error)
func (ncp *CAPool) BlocklistFingerprint(f string)
```

**Шифрование ключей**:

```go
func EncryptAndMarshalSigningPrivateKey(curve Curve, b []byte, passphrase []byte, kdfParams *Argon2Parameters) ([]byte, error)
func DecryptAndUnmarshalSigningPrivateKey(passphrase, b []byte) (Curve, []byte, []byte, error)
```

**Поддержка PKCS#11** (v1.10+): через `SignWith()` + `SignerLambda`, позволяющий делегировать подписание HSM без извлечения приватного ключа[^13]. Ограничение: только P256 curve.

Это означает, что **нет необходимости вызывать `nebula-cert` binary** — вся функциональность доступна как Go-библиотека, включая создание CA, подписание сертификатов, валидацию и шифрование ключей.

## Хранение CA-ключей

### Иерархия ключей

Рекомендуемая архитектура — двухуровневая PKI[^14][^15]:

```
Root CA (offline, зашифрован, используется 1-2 раза в год)
    ↓
Intermediate CA (online, подписывает хостовые сертификаты)
    ↓
Host Certificates (распространяются на узлы)
```

**Root CA**: самоподписанный, хранится offline. Используется только для подписания intermediate CA. Компрометация = полная замена PKI.

**Intermediate CA**: подписан root CA, работает online. Компрометация = отзыв и перевыпуск intermediate без затрагивания root.

Nebula поддерживает указание нескольких CA в `pki.ca`, что позволяет плавную ротацию[^16].

### Варианты хранения

#### 1. Встроенное шифрование Nebula (простейший вариант)

С версии 1.7.0 `nebula-cert` поддерживает `-encrypt` при генерации CA[^16]:

- AES-256-GCM + Argon2id для деривации ключа
- Параметры Argon2: 1 итерация, 4 потока, 2 GB RAM (RFC-рекомендации)

Программно через библиотеку:

```go
encrypted, err := cert.EncryptAndMarshalSigningPrivateKey(
    cert.Curve_CURVE25519, privateKey, passphrase,
    cert.NewArgon2Parameters(2*1024*1024, 4, 1),
)
```

**Подходит для**: малых команд, домашних сетей, PoC.

#### 2. HSM через PKCS#11 (v1.10+)

Приватный ключ никогда не покидает аппаратный модуль[^13]:

```
pkcs11:id=1234;object=nebula-key?module-path=/usr/lib64/pkcs11/my-module.so&pin-source=/path/to/pin-file
```

**Ограничения**: только P256 curve (не Curve25519), требует cgo-сборки, совместимые устройства (YubiKey HSM, YubiHSM 2).

**Подходит для**: production-среды с compliance-требованиями.

#### 3. HashiCorp Vault

Vault PKI engine может выступать как online CA[^17]. Нативной интеграции с Nebula нет, но возможна через API:

1. Root CA хранится offline (или в Vault с auto-unseal)
2. Intermediate CA в Vault PKI engine
3. Self-hosted сервис запрашивает подписание через Vault API
4. `SignWith()` + `SignerLambda` в Go-коде делегирует подписание Vault

**Подходит для**: организаций с существующей Vault-инфраструктурой.

#### 4. Cloud KMS (AWS KMS, GCP Cloud KMS)

Ключ генерируется и хранится в облачном HSM, подписание через API[^18]:

- AWS KMS: FIPS 140-2 Level 2/3
- GCP Cloud HSM: FIPS 140-2 Level 3
- Стоимость: $1-5/мес за ключ

**Подходит для**: распределённых команд с облачной инфраструктурой.

### Рекомендуемая модель для self-hosted

| Масштаб | Root CA | Intermediate CA | Стоимость |
|---|---|---|---|
| Домашняя сеть | Encrypted file + USB backup | Encrypted file на сервере | $0 |
| Малая команда | YubiKey, offline | Encrypted file + passphrase manager | $50-100 |
| Production | YubiKey/HSM, air-gapped | PKCS#11 HSM или Vault | $100-500 |
| Enterprise | Cloud KMS, geo-redundant | Vault PKI engine | $5-50/мес |

## Доставка сертификатов на устройства

### Протоколы enrollment

#### Token-Based Enrollment (рекомендуемый)

Модель Defined Networking — простейшая и наиболее практичная[^6][^7]:

1. Администратор генерирует одноразовый enrollment token (с TTL)
2. Token передаётся на устройство out-of-band (QR, email, CLI)
3. Устройство отправляет token + свой публичный ключ на enrollment endpoint
4. Сервис валидирует token, подписывает сертификат, возвращает cert + config
5. Token инвалидируется

**Решает bootstrap problem**: устройство без сертификата аутентифицируется одноразовым кодом.

**Преимущества**:
- Минимальная сложность
- Аудит-трейл (какой code создал какой хост)
- Работает за NAT без обратной связности
- Можно реализовать как signed JWT с payload (hostname, role, expiry)

#### EST (RFC 7030)

Стандартизированный протокол с поддержкой re-enrollment[^9][^19]:

- `/cacerts` — получение CA-сертификатов
- `/simpleenroll` — начальный enrollment с PKCS#10 CSR
- `/simplereenroll` — обновление сертификата
- `/serverkeygen` — серверная генерация ключей (для constrained devices)

**Преимущества**: RFC-стандарт, proof-of-possession, встроенный re-enrollment.
**Недостатки**: сложнее token-based, требует TLS-инфраструктуру.

#### Безопасный workflow без передачи приватного ключа

Nebula поддерживает генерацию ключей на устройстве[^20]:

1. На устройстве: `nebula-cert keygen -out-key host.key -out-pub host.pub`
2. Только `host.pub` отправляется на CA
3. CA подписывает: `nebula-cert sign -in-pub host.pub ...`
4. Подписанный `host.crt` возвращается на устройство

> "Private keys never leave their intended device, eliminating transfer risk"[^20].

В API-модели: устройство генерирует keypair, отправляет public key с enrollment token, получает подписанный сертификат.

### Push vs Pull

| Модель | Механизм | Задержка | За NAT | Сложность |
|---|---|---|---|---|
| **Pull** (DN model) | Агент опрашивает сервер каждые N секунд | До N секунд | Работает | Низкая |
| **Push** | Сервер инициирует доставку (WebSocket/gRPC stream) | Мгновенно | Требует persistent connection | Высокая |
| **Hybrid** | Pull + event notification | Секунды | Работает с fallback | Средняя |

**Рекомендация**: Pull-модель (как у DN) — проще, работает за NAT, масштабируется. Интервал 30-60 секунд достаточен для большинства сценариев.

### Автоматическая ротация сертификатов

Паттерн short-lived certificates с автоматическим обновлением:

1. Выдавать сертификаты с TTL 7-30 дней (вместо года)
2. Агент проверяет срок при каждом poll
3. При оставшихся < 20% времени жизни — запрос на re-enrollment
4. Сервер подписывает новый сертификат тем же CA
5. Агент перезагружает PKI через SIGHUP (без перезапуска Nebula)[^13]

Для ротации самого CA — четырёхшаговый процесс[^16]:
1. Генерация нового CA
2. Распространение обоих CA (старый + новый) на все узлы
3. Перевыпуск хостовых сертификатов новым CA
4. Удаление старого CA

## Управление мобильными устройствами

### Mobile Nebula

Официальное приложение от Defined Networking[^21]:

| Параметр | Значение |
|---|---|
| Платформы | iOS 14.0+, Android |
| Фреймворк | Flutter + Go (networking) |
| Сертификаты | v1 и v2, P256 для managed |
| Сети | Множественные (одна активная) |
| Always-on | Да (автоматическое переподключение) |
| Relay | Поддерживается |
| Репозиторий | github.com/DefinedNet/mobile_nebula |

### Enrollment на мобильных устройствах

**Defined Networking** использует deep links[^22]:
1. Администратор генерирует enrollment link
2. Пользователь открывает link на устройстве с установленным Mobile Nebula
3. Приложение автоматически инициирует enrollment
4. Сертификат и конфигурация доставляются через managed API

**Self-hosted альтернативы**:
- QR-код с enrollment token + server URL
- Deep link / Universal link, открывающий приложение с параметрами
- Ручной ввод: вставка сертификата и ключа в UI приложения

### Платформенные ограничения

**iOS**:
- Третьи VPN-приложения **не могут** обеспечить true always-on без MDM[^23]
- Mobile Nebula реализует "always-on" как автоматическое переподключение при старте
- True always-on (блокировка трафика вне VPN) требует MDM + IKEv2 (не Nebula)
- NEPacketTunnelProvider продолжает работу при завершении host app

**Android**:
- VpnService работает как foreground service — стабильно в фоне[^24]
- Android 14+ ужесточает lifecycle для background services
- Proper foreground service с notification — минимальное влияние на батарею

### Управление конфигурацией

Для self-hosted сценария обновление конфигурации на мобильных устройствах — нерешённая проблема:
- Нет механизма автоматического push обновлений без DN backend
- Ручное обновление YAML-файлов через UI приложения
- MDM может автоматизировать установку и начальный enrollment, но не ongoing updates

**Решение**: агент внутри приложения (аналог DNClient), опрашивающий self-hosted backend. Требует форк Mobile Nebula или собственное приложение.

## Управление lighthouse и relay

### Архитектура высокой доступности

Рекомендуемая конфигурация для production[^25][^26]:

```
2-3 Lighthouse (географически распределённые)
    ↓
Клиенты указывают ВСЕ lighthouse в конфигурации
    ↓
Автоматический failover при недоступности любого lighthouse
    ↓
1-2 Dedicated Relay (отдельно от lighthouse)
```

**Lighthouse**:
- Stateless реестр адресов, минимальные ресурсы ($5-6/мес VPS)[^2]
- Клиенты опрашивают все указанные lighthouse и агрегируют результаты
- Нет встроенного автоматического failover — клиент просто пропускает недоступный[^25]
- DNS-serving (экспериментальная функция): A-записи по hostname из сертификата[^27]

**Relay** (с v1.6.0):
- Для случаев, когда прямое P2P невозможно (symmetric NAT, CGNAT)[^28]
- End-to-end шифрование сохраняется — relay не читает трафик
- Отдельная роль от lighthouse
- Ограничение: "relay не может быть relay для relay"

### Автоматизация lifecycle

В self-hosted решении management plane должен:

1. **Provisioning**: создать lighthouse/relay в панели → сгенерировать сертификат → enrollment
2. **Мониторинг**: отслеживать handshake success/failure, tunnel count, latency
3. **Обновление конфигурации**: при добавлении нового lighthouse — обновить `static_host_map` на всех узлах (через pull-agent)
4. **Ротация**: обновление сертификатов lighthouse без downtime (SIGHUP reload)

DN обрабатывает обновление lighthouse-конфигурации в течение 60-секундного окна без перезапуска хостов[^29].

## Сравнение с Headscale (архитектурные уроки)

Headscale — успешный пример self-hosted control plane для Tailscale[^30]. Ключевые архитектурные решения, применимые к Nebula:

### Что перенять

| Решение Headscale | Применение к Nebula |
|---|---|
| **gRPC-Gateway**: REST и gRPC синхронизированы через protobuf[^31] | Единый API definition, автогенерация REST из gRPC |
| **Pre-auth keys**: одноразовые ключи для enrollment | Token-based enrollment (аналогично DN) |
| **OIDC интеграция**: SSO через внешних провайдеров | OAuth2/OIDC для административного доступа |
| **SQLite storage**: единый файл, простое резервирование | Достаточно для management plane |
| **Single binary**: простой deployment | Go binary без внешних зависимостей |
| **Policy as code**: ACL в HuJSON/YAML | Firewall rules как конфигурация |

### Что не переносится

- **Совместимость с существующим клиентом**: Headscale работает с official Tailscale client. Для Nebula нет аналогичного managed-клиента — придётся создавать свой агент
- **Key distribution через control plane**: Tailscale/Headscale управляет WireGuard-ключами централизованно. Nebula использует PKI — ключи в сертификатах, а не в control plane
- **DERP relay**: TCP-based relay Tailscale. Nebula имеет собственный UDP relay

## Дискуссионные вопросы и противоречия

### Централизация CA vs. безопасность

Fundamental trade-off: удобство управления требует online-доступа к CA-ключу, что увеличивает поверхность атаки[^8][^16]. Варианты компромисса:

- **Intermediate CA online, root offline** — компрометация intermediate ≠ полная компрометация
- **HSM/PKCS#11** — ключ online, но защищён аппаратно
- **Short-lived certificates** — компрометация ограничена по времени

Nebula Tower хранит CA на сервере (максимальное удобство, минимальная безопасность)[^8]. DN не раскрывает архитектуру хранения (managed service). Рекомендуемый баланс: intermediate CA на сервере с шифрованием, root CA offline.

### Отсутствие push-механизма в Nebula

Blocklist не распространяется через lighthouse[^13] — администратор должен обновить конфигурацию на всех узлах. Для сетей с 100+ узлами это требует configuration management. Self-hosted решение должно включать этот механизм: агент на каждом узле, получающий обновлённый blocklist через poll.

### Мобильные устройства без собственного агента

Mobile Nebula — open-source (MIT), но предназначен для Managed Nebula. Self-hosted enrollment требует либо форка с добавлением pull-агента, либо ручной конфигурации. Это главный gap — автоматизация мобильных устройств невозможна без модификации клиента.

### Зрелость экосистемы

Ни один из существующих open-source проектов не достиг production-ready состояния[^8][^9][^10]. Nebula Tower — v0.1.1, nebula-est — заброшен, nebula-manager — Bash-скрипт без API. Это подтверждает необходимость нового решения, но означает, что придётся строить практически с нуля.

## Архитектура предлагаемого решения

### Обзор компонентов

```
┌─────────────────────────────────────────────┐
│              Management Server              │
│                                             │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
│  │ REST/   │  │ PKI      │  │ Config    │  │
│  │ gRPC    │  │ Engine   │  │ Generator │  │
│  │ API     │  │          │  │           │  │
│  └────┬────┘  └────┬─────┘  └─────┬─────┘  │
│       │            │              │         │
│  ┌────┴────────────┴──────────────┴─────┐   │
│  │           SQLite / PostgreSQL        │   │
│  └──────────────────────────────────────┘   │
└─────────────────────┬───────────────────────┘
                      │ HTTPS (pull every 30-60s)
          ┌───────────┼───────────┐
          │           │           │
     ┌────┴────┐ ┌────┴────┐ ┌───┴─────┐
     │ Agent   │ │ Agent   │ │ Agent   │
     │ (Linux) │ │ (macOS) │ │ (mobile)│
     └─────────┘ └─────────┘ └─────────┘
          │           │           │
     ┌────┴────┐ ┌────┴────┐ ┌───┴─────┐
     │ Nebula  │ │ Nebula  │ │ Nebula  │
     └─────────┘ └─────────┘ └─────────┘
```

### Management Server

**Язык**: Go — для прямого использования `nebula/cert` библиотеки.

**API**: gRPC + gRPC-Gateway (автогенерация REST), аналогично Headscale[^31].

**Storage**: SQLite (для простоты) или PostgreSQL (для масштабирования).

**Функции**:
- PKI Engine: генерация CA, подписание сертификатов, blocklist management
- Config Generator: шаблонизация `config.yml` для каждого хоста
- Enrollment: token-based, с одноразовыми кодами
- Host Management: CRUD хостов, ролей, групп
- Firewall Rules: управление правилами, распространение через pull
- Lighthouse/Relay Management: lifecycle, мониторинг

### Agent (замена DNClient)

**Язык**: Go — кросс-платформенный, включая мобильные через gomobile.

**Поведение**:
1. Enrollment: принимает token, генерирует keypair, отправляет public key на сервер
2. Poll: каждые 30-60 секунд запрашивает обновления (cert, config, blocklist)
3. Apply: при получении обновлений — записывает файлы, отправляет SIGHUP Nebula
4. Report: отправляет статус (handshake count, uptime, version) на сервер

**Платформы**: Linux, macOS, Windows. Для мобильных — интеграция в форк Mobile Nebula.

### Enrollment Flow

```
Admin                    Server                    Device
  │                        │                         │
  │ POST /hosts            │                         │
  │ (name, role, groups)   │                         │
  │───────────────────────>│                         │
  │                        │                         │
  │ enrollment_token       │                         │
  │<───────────────────────│                         │
  │                        │                         │
  │ (передаёт token        │                         │
  │  out-of-band)          │                         │
  │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>│
  │                        │                         │
  │                        │  POST /enroll           │
  │                        │  (token, public_key)    │
  │                        │<────────────────────────│
  │                        │                         │
  │                        │  Sign cert with         │
  │                        │  intermediate CA        │
  │                        │                         │
  │                        │  {cert, ca_cert, config}│
  │                        │────────────────────────>│
  │                        │                         │
  │                        │                         │ Save files
  │                        │                         │ Start Nebula
  │                        │                         │
  │                        │  GET /updates (poll)    │
  │                        │<────────────────────────│
  │                        │  {no_changes}           │
  │                        │────────────────────────>│
```

### PKI Architecture

```
Root CA (Curve25519 или P256)
├── Encrypted with AES-256-GCM + Argon2id
├── Stored: offline (USB/HSM) или Vault
├── Used: only to sign intermediate CAs
│
└── Intermediate CA (online)
    ├── Stored: encrypted on server или PKCS#11 HSM
    ├── Used: sign host certificates
    ├── TTL: 6-12 месяцев
    │
    ├── Host Certificate (lighthouse)
    │   └── TTL: 30-90 дней
    ├── Host Certificate (server)
    │   └── TTL: 7-30 дней
    └── Host Certificate (mobile)
        └── TTL: 7-30 дней
```

### Что можно переиспользовать

| Компонент | Источник | Как использовать |
|---|---|---|
| PKI-операции | `nebula/cert` Go package[^12] | Прямой import, без CLI |
| Nebula core | `slackhq/nebula` MIT[^1] | Data plane без изменений |
| Mobile Nebula | `DefinedNet/mobile_nebula` MIT[^21] | Форк с добавлением pull-агента |
| Enrollment protocol design | Defined Networking API[^7] | Token-based flow |
| API design pattern | Headscale gRPC-Gateway[^31] | Protobuf → REST + gRPC |
| Config templates | Nebula docs[^2] | Шаблонизация `config.yml` |
| EST re-enrollment | nebula-est (концепция)[^9] | Паттерн auto-renewal |

### Этапы разработки

**MVP (Phase 1)**: Management server + Linux agent

- REST API для управления хостами
- Token-based enrollment
- PKI engine (CA creation, cert signing через `nebula/cert`)
- Config generation
- Pull-based agent для Linux
- SQLite storage

**Phase 2**: Web UI + advanced PKI

- React/Svelte веб-интерфейс
- Intermediate CA support
- Certificate auto-renewal
- Blocklist distribution
- Lighthouse/relay management

**Phase 3**: Mobile + monitoring

- Форк Mobile Nebula с pull-агентом
- QR-code enrollment
- Host status monitoring
- Audit logging

**Phase 4**: Enterprise features

- OIDC/SSO authentication
- RBAC for administrators
- PostgreSQL support
- Multi-network support
- PKCS#11/Vault integration

## Quality Metrics

| Метрика | Значение |
|---|---|
| Источники найдены | 42 |
| Источники процитированы | 31 |
| Типы источников | official: 14, github: 9, blog: 5, RFC: 3 |
| Покрытие цитатами | 92% |
| Исследованные подвопросы | 7 |
| Раунды исследования | 2 (initial + iterative deepening) |
| Вопросы, возникшие в ходе анализа | 5 |
| Вопросы разрешены | 4 |
| Вопросы с недостаточными данными | 1 (DN internal PKI architecture) |

[^1]: https://github.com/slackhq/nebula — Nebula open-source repository, MIT license
[^2]: https://nebula.defined.net/docs/ — Official Nebula documentation
[^3]: https://www.defined.net/ — Defined Networking managed service
[^4]: https://docs.defined.net/get-started/quick-setup/ — Managed Nebula quick setup guide
[^5]: https://docs.defined.net/glossary/dnclient/ — DNClient documentation
[^6]: https://docs.defined.net/guides/automating-host-creation/ — Automating host creation with API
[^7]: https://docs.defined.net/api/defined-networking-api/ — Defined Networking REST API
[^8]: https://github.com/transformerlab/nebula-tower — Nebula Tower, Python/React management UI
[^9]: https://github.com/securityresearchlab/nebula-est — NEST: Enrollment over Secure Transport for Nebula
[^10]: https://github.com/jordanhillis/nebula-manager — nebula-manager CLI tool v1.1.0
[^11]: https://www.shieldoo.io/ — Shieldoo Mesh (SaaS only, code removed from GitHub)
[^12]: https://pkg.go.dev/github.com/slackhq/nebula/cert — Nebula cert Go package API
[^13]: https://nebula.defined.net/docs/config/pki/ — Nebula PKI configuration (PKCS#11, blocklist, disconnect_invalid)
[^14]: https://www.ncsc.gov.uk/collection/in-house-public-key-infrastructure/introduction-to-public-key-infrastructure/ca-hierarchy — NCSC CA hierarchy guide
[^15]: https://blog.cloudflare.com/how-to-build-your-own-public-key-infrastructure/ — Cloudflare PKI architecture guide
[^16]: https://nebula.defined.net/docs/guides/rotating-certificate-authority/ — Nebula CA rotation guide
[^17]: https://developer.hashicorp.com/vault/docs/secrets/pki — HashiCorp Vault PKI secrets engine
[^18]: https://cloud.google.com/kms/docs/hsm — Google Cloud HSM documentation
[^19]: https://datatracker.ietf.org/doc/html/rfc7030 — RFC 7030: Enrollment over Secure Transport (EST)
[^20]: https://nebula.defined.net/docs/guides/sign-certificates-with-public-keys/ — Sign certificates with public keys (private key never leaves device)
[^21]: https://github.com/DefinedNet/mobile_nebula — Mobile Nebula app (Flutter + Go)
[^22]: https://www.defined.net/mobile-enrollment/ — Defined Networking mobile enrollment
[^23]: https://developer.apple.com/documentation/networkextension/netunnelprovidermanager — Apple NEPacketTunnelProvider
[^24]: https://developer.android.com/about/versions/oreo/background — Android background execution limits
[^25]: https://nebula.defined.net/docs/config/lighthouse/ — Lighthouse configuration
[^26]: https://nebula.defined.net/docs/config/relay/ — Relay configuration
[^27]: https://nebula.defined.net/docs/guides/using-lighthouse-dns/ — Lighthouse DNS serving
[^28]: https://www.defined.net/blog/announcing-relay-support-in-nebula/ — Relay support announcement (v1.6.0)
[^29]: https://www.defined.net/blog/newsletter-admin-api-cert-rotation-multiple-lighthouses/ — DN newsletter: Admin API, cert rotation, multiple lighthouses
[^30]: https://github.com/juanfont/headscale — Headscale: self-hosted Tailscale control server
[^31]: https://headscale.net/stable/ref/api/ — Headscale API documentation (gRPC-Gateway pattern)
