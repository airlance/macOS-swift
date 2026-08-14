# AGENTS.md — macOS Swift client (workspace/macOS-swift)

Карта архитектуры macOS-клиента. См. также корневой `../../AGENTS.md` для
кросс-проектных инвариантов (общих с Go-бэкендом), и `TASK_concurrency.md` в этой
папке для активного плана работ по переходу на новую concurrency-модель.

---

## 1. Обзор

- **Язык:** Swift, цель — **Swift 6 language mode**, strict concurrency checking.
- **Сборка:** Bazel (`BUILD.bazel`, `MODULE.bazel`) для app-таргета (`:Airlance`) и
  модуля `AirlanceClient` (`//submodules/AirlanceClient:AirlanceClient`).
- **UI:** AppKit (`AppDelegate`, `NSViewController`-based auth flow).
- **Крипто:** CryptoKit (`Curve25519`, `ChaChaPoly`) — Noise IK handshake, зеркало
  Go-реализации `internal/noiseik/` побайтово.
- **Wire-протокол:** FlatBuffers, генерируемый Swift-код из `../../proto/schema.fbs`
  через `flatc` (не автоматизировано `make`-таргетом, см. §5).

---

## 2. Структура модулей

```
workspace/macOS-swift/
├── Airlance/                          ← App target (AppKit UI)
│   ├── AppDelegate.swift
│   ├── Auth/                          ← Email OTP + GitHub OAuth UI flow
│   │   ├── AuthCoordinator.swift
│   │   ├── AuthWindowController.swift
│   │   ├── EmailStepViewController.swift
│   │   ├── OTPStepViewController.swift
│   │   └── GithubWaitingViewController.swift
│   └── AuthenticatedViewController.swift
│
└── submodules/AirlanceClient/         ← Bazel swift_library target
    └── Sources/AirlanceClient/
        ├── AirlanceClient.swift       ← Facade: публичный API пакета (см. §3)
        ├── AuthClient.swift           ← Email OTP auth поверх NoiseTransport.request(_:expecting:)
        ├── ConnectionState.swift      ← Enum состояний подключения (.connected, .connecting, ...)
        ├── IncomingEvent.swift        ← Enum серверных push-событий (MessageUpdate, ...)
        ├── DeviceIdentity.swift       ← device keypair (Keychain), fingerprint
        ├── GithubAuthCoordinator.swift← GitHub OAuth (browser + deep link)
        ├── Framing.swift              ← зеркало internal/transport/framing.go
        ├── TCPConnection.swift        ← NWConnection wrapper, async readFrame/writeFrame
        ├── Noise/
        │   ├── CipherState.swift      ← зеркало Noise CipherState (ChaChaPoly, nonce counter)
        │   ├── SymmetricState.swift   ← зеркало Noise SymmetricState (MixHash/MixKey)
        │   ├── HandshakeState.swift   ← Noise IK message1/message2, зеркало internal/noiseik/noiseik.go
        │   └── NoiseTransport.swift   ← actor: владелец крипто-состояния, read loop, dispatch, AsyncStream
        └── Protocol/
            ├── ProtocolCodec.swift    ← FlatBuffers envelope encode/decode
            └── schema_generated.swift ← сгенерировано flatc, НЕ редактировать руками
```

---

## 3. Публичный API `AirlanceClient` (facade)

`AirlanceClient` — единственная точка входа для UI-слоя. UI никогда не работает с
`NoiseTransport`/`TCPConnection`/`Noise*` напрямую.

Публичный API:
- `connect() async throws` — TCP connect + Noise IK handshake + запуск read loop и heartbeat.
- `close()` — закрытие соединения и очистка очереди запросов.
- `incomingEvents: AsyncStream<IncomingEvent>?` — поток входящих server-push событий.
- `connectionState: AsyncStream<ConnectionState>?` — поток состояний соединения.
- `establishSession() async throws -> AuthSession?` — resume/new session по сохранённому
  в Keychain `session_id`, см. подробный флоу в doc-комментарии метода.
- `signInWithGithub(...) async throws -> AuthSession` — полный OAuth flow (macOS only).
- `auth: AuthClient?` — email OTP операции.
- `devicePublicKeyHex()`, `deviceFingerprint()` — синхронные, чистые.

---

## 4. Concurrency-модель (Swift 6)

### Принцип: facade — обычный класс, крипто-состояние — actor

```
final class AirlanceClient        ← НЕ actor. Обычный объект, синхронные геттеры остаются sync.
    └── actor NoiseTransport      ← ЕДИНСТВЕННЫЙ владелец send/recv CipherState, read loop, оба AsyncStream
            └── TCPConnection     ← final class, обёртка NWConnection (сама изолирована своей queue)
    └── GithubAuthCoordinator     ← отдельный Sendable-компонент, не под NoiseTransport
```

**Почему actor именно для `NoiseTransport`, не для всего клиента:**
- `CipherState.nonce` — монотонный счётчик, инкрементируемый на каждый encrypt/decrypt.
  Гонка здесь — не просто баг многопоточности, а **криптографическая катастрофа**
  (повторное использование nonce в ChaCha20-Poly1305 ломает confidentiality/integrity).
  Actor isolation даёт статическую гарантию отсутствия гонки на этом состоянии.
- Если actor'ом сделать весь `AirlanceClient`, каждый синхронный геттер
  (`devicePublicKeyHex()`, UI-биндинги в AppKit-контроллерах) вынужден `await`,
  создавая трение без выигрыша — эти операции не трогают крипто-состояние.
- **Actor reentrancy — не панацея.** `connect()` внутри `NoiseTransport` обязан
  guard'иться явным состоянием (`.idle → .connecting → .connected`), иначе повторный
  вызов `connect()` во время уже идущего handshake проскочит между `await`-точками
  и получит два параллельных handshake на одном соединении. Actor защищает только
  от гонки *данных*, не от гонки *логики* — guard пишется руками.

### Два независимых `AsyncStream`

Не смешивать в один enum — разная семантика жизненного цикла:

1. **`connectionState: AsyncStream<ConnectionState>`**
   `.disconnected | .connecting | .connected | .reconnecting(attempt: Int) | .failed(String)`
   Переживает множество попыток реконнекта. Владелец — `NoiseTransport`.

2. **`incomingEvents: AsyncStream<IncomingEvent>`**
   Расшифрованные application-фреймы после handshake (входящие сообщения, presence,
   session-revoked и т.д. — маппится из `union Body` в схеме). Пересоздаётся при
   каждом новом соединении (жизненный цикл привязан к сессии, не к процессу).

### Heartbeat — internal, не публичный

Ping/Pong (union Body индексы 1, 2) обрабатываются **внутри** read loop `NoiseTransport`
и наружу не просвечивают — это транспортная забота, не доменное событие. Единственное
наблюдаемое следствие: 3 пропущенных heartbeat подряд → триггерит переход
`connectionState` в `.reconnecting`/`.failed`, не отдельный поток событий.

### Read loop — один на соединение

`TCPConnection.readFrame()` не поддерживает конкурентные вызовы (`NWConnection.receive`
не рассчитан на гонку). Поэтому ровно один `Task` внутри `NoiseTransport` непрерывно
читает фреймы, расшифровывает (actor-isolated → nonce increment safe), и
демультиплексирует: heartbeat → internal handler, ожидающие запросы → continuation,
остальное → `incomingEvents.yield(...)`.

```swift
actor NoiseTransport {
    private var sendCipher: CipherState?
    private var recvCipher: CipherState?
    private var raw: TCPConnection?
    private(set) var state: NoiseTransportState = .idle
    private var readLoopTask: Task<Void, Never>?
    private var heartbeatTask: Task<Void, Never>?

    nonisolated let connectionState: AsyncStream<ConnectionState>
    nonisolated let incomingEvents: AsyncStream<IncomingEvent>
}
```

### Request/response поверх read loop — диспетчеризация по `request_id`

Read loop — **единственный** читатель `raw.readFrame()` и стартует сразу в конце
`connect()`, а не после auth.

`AuthClient`/`establishSession()`/`signInWithGithub()` отправляют запросы через:

```swift
func request(_ frame: [UInt8], expecting requestID: UInt64) async throws -> Protocol__Envelope
```

Внутри read loop, после decode `Envelope`:
- `request_id` совпадает с ожидающим запросом (есть continuation в
  `pendingRequests: [UInt64: CheckedContinuation<Protocol__Envelope, Error>]`) → резолвим её,
  **не** уходит в `incomingEvents`.
- `request_id == 0` (или нет совпадения) и тип — не heartbeat → server-push,
  `incomingContinuation.yield(mapped)`.
- heartbeat (Ping/Pong) → внутренний handler, не в `incomingEvents` и не в
  `pendingRequests`.

`AuthClient` генерирует `requestID` через `RequestIDGenerator()` и вызывает
`transport.request(frame, expecting: requestID)`. Публичная сигнатура `AuthClient` не меняется.

---

## 5. Известный блокер — РЕШЁН, см. §5.1 для протокольного инварианта

**AEAD verification failure на Noise handshake message 1** — `chacha20poly1305: message
authentication failed`. Причина найдена и подтверждена рантаймом: отсутствовал
`MixHash(prologue)` в `HandshakeState.init` (см. §5.1 — **не путать это с решением,
это была причина бага, не фикс**). Также убраны debug-`print()`, дампившие приватные
ключи/shared secrets в открытом виде (`ephemeral`/`staticKeypair.rawRepresentation`,
`esShared`, `ssShared`) — были в `HandshakeState.writeMessage1()` и старом
`NoiseIKHandshake.clientHandshake`, теперь отсутствуют в `NoiseTransport`/`HandshakeState`.

### 5.1. ПРОТОКОЛЬНЫЙ ИНВАРИАНТ — `mixHash([])` в `HandshakeState.init` ОБЯЗАТЕЛЕН, НЕ УДАЛЯТЬ

**Зафиксировано и подтверждено рантаймом против Go-сервера. Это финальное решение.**

`HandshakeState.init` обязан выполнять **два отдельных** вызова `mixHash`, в этом порядке:

```swift
symmetricState.mixHash([])                                            // (1) Initialize(): MixHash(prologue)
symmetricState.mixHash([UInt8](remoteStaticPublicKey.rawRepresentation)) // (2) pre-message: MixHash(rs)
```

Это два разных обязательных шага Noise spec §5.3 (`Initialize()` → `MixHash(prologue)`,
затем pre-message pattern `<- s` → `MixHash(rs)`), а не дубль и не опечатка. Хотя
`prologue` у нас пустой (`[]`), вызов `mixHash([])` **не является no-op**:
`h = SHA256(h + data)`, и `SHA256(h + [])` — это лишний хэш-раунд, который меняет `h`.
Без него `h` расходится с Go-сервером (`flynn/noise`: `Config.Prologue` по умолчанию
`nil`, но `NewHandshakeState` безусловно вызывает `MixHash(prologue)` внутри) —
это и было причиной `chacha20poly1305: message authentication failed` на message 1.

Ранее эта строка уже один раз ошибочно удалялась как "лишняя" (с обоснованием, что раз
`prologue` пустой, вызов ничего не меняет) — это и вызвало регресс бага. **Если этот
инвариант снова покажется избыточным или подозрительным при рефакторинге/ревью
(в т.ч. AI-агентом) — это не повод его убирать.** Проверено по спеке (Noise §5.3) и
сверено побайтово с серверной реализацией; см. также комментарий прямо в
`HandshakeState.swift` над этим кодом.

---

## 6. FlatBuffers кодген (Swift-сторона)

В отличие от Go (`make gen` в `workspace/api`), для Swift-клиента кодген из
`../../proto/schema.fbs` в `schema_generated.swift` пока **не автоматизирован** —
выполняется вручную через `flatc --swift`. См. корневой `README.md` / `scripts/gen-fbs.sh`
для версии `flatc`, которая должна совпадать между Go и Swift кодгеном (иначе схемы
разойдутся молча).

---

## 7. Известные незакрытые вопросы

- Graceful shutdown / переподключение при потере сети — базовые механизмы (`connectionState`,
  reconnect heartbeat detection) внедрены; внешний координатор переподключения может развиваться.
- `AirlanceClient.swift` сейчас — единственная точка входа и facade, и (частично)
  use-case слой одновременно (`establishSession()` содержит бизнес-логику resume/new
  session fallback). Решение зафиксировано: пока НЕ дробить дальше на отдельные
  use-case-типы по аналогии с Go `internal/usecase/*` — facade остаётся единой точкой
  входа с делегированием во внутренние `*Client`/`NoiseTransport`.