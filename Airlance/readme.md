# Generated flatbuffers Swift types

`common_generated.swift`, `login_generated.swift`, `session_generated.swift`,
and `qrlogin_generated.swift` in this directory were produced by:

```sh
flatc --version   # 25.12.19
flatc --swift --gen-object-api -o Sources/AirlanceKit/Generated \
  fbs/auth/common.fbs fbs/auth/login.fbs fbs/auth/session.fbs fbs/auth/qrlogin.fbs
```

`auth.fbs` was split into these four files on the server side (see
`fbs/auth/*.fbs`) — `common.fbs` holds `Platform`/`ClientContext`,
shared via `include "common.fbs";` from the other three. flatc does not
duplicate included types into each output file, so `Platform` and
`ClientContext` only exist in `common_generated.swift`.

They are committed as-is (not regenerated at build time) so the exact
types `MessageConformances.swift`/`MessageAliases.swift` reference are
stable. **Regenerate whichever file changes whenever the matching
`.fbs` changes on the server**, and re-diff
`grep -h '^public struct authv1_' *_generated.swift` against
`MessageConformances.swift`'s extension list — a schema change that
adds/removes/renames a table needs a matching update there and in
`MessageAliases.swift`, and `AirlanceClient.swift`'s request-builders if
fields changed.

## Confirmed facts about this generator version (25.12.19)

- Namespace `authv1` → Swift type prefix `authv1_` (lowercase, matches
  the schema verbatim) — NOT `Authv1_`. This was wrong in an earlier
  draft of this client; fixed throughout after actually running flatc.
- No `getRootAsXxx` method exists on generated table types. Decode via
  the runtime's free function: `let x: SomeTable = try getCheckedRoot(byteBuffer: &buf)`
  (generic, inferred from the declared type). See `FBMsg.unmarshalFB`.
- `pack`/`unpack` are exactly as expected: `SomeTable.pack(&builder, obj:
  &someT)` and `someTableInstance.unpack() -> SomeTableT`.
- Every generated table struct conforms to `FlatBufferTable,
  FlatbuffersVectorInitializable, Verifiable, ObjectAPIPacker` — so
  `FlatBufferGeneratedTable` conformances in `MessageConformances.swift`
  are empty extensions, nothing to implement.
- `authv1_QRLoginEventT.payload` is a flatbuffers union
  (`authv1_QRLoginEventPayloadUnion`, with `.type` /
  `.value: NativeObject?`), not a plain optional field — callers must
  switch on `.type` and downcast `.value`.
- `flatbuffers/swift`'s package also ships a `Common` module that
  generated code conditionally imports (`#if canImport(Common)`) — not
  currently required by anything in these files' actual code paths for
  this schema, left as the harmless no-op `#if` flatc emitted.