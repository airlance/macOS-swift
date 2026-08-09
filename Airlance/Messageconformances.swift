import FlatBuffers

// Confirmed against real `flatc --swift --gen-object-api` output
// (flatc 25.12.19). Every table struct listed here already implements
// everything `FlatBufferGeneratedTable` requires (FlatBufferTable,
// Verifiable, `unpack()`, the non-optional `pack(_:obj:)` overload) as
// part of its generated `ObjectAPIPacker` conformance — these are empty
// extensions, not reimplementations.
//
// Generated from fbs/auth/{common,login,session,qrlogin}.fbs (split
// from a single auth.fbs — see each *_generated.swift file's origin).
// The real namespace prefix is `authv1_` (lowercase after the
// underscore, matching every file's `namespace authv1;` verbatim), NOT
// `Authv1_` as originally assumed before running flatc. If any .fbs is
// regenerated with a different flatc version, diff this file's type
// list against `grep -h '^public struct authv1_' *_generated.swift`
// before trusting it still matches.

extension authv1_ClientContext: FlatBufferGeneratedTable {}

extension authv1_LoginByGithubRequest: FlatBufferGeneratedTable {}
extension authv1_LoginByGithubResponse: FlatBufferGeneratedTable {}

extension authv1_ResumeSessionRequest: FlatBufferGeneratedTable {}
extension authv1_ResumeSessionResponse: FlatBufferGeneratedTable {}

extension authv1_TerminateSessionRequest: FlatBufferGeneratedTable {}
extension authv1_TerminateSessionResponse: FlatBufferGeneratedTable {}

extension authv1_ListSessionsRequest: FlatBufferGeneratedTable {}
extension authv1_ListSessionsResponse: FlatBufferGeneratedTable {}
extension authv1_SessionInfo: FlatBufferGeneratedTable {}

extension authv1_KillSessionRequest: FlatBufferGeneratedTable {}
extension authv1_KillSessionResponse: FlatBufferGeneratedTable {}

extension authv1_GenerateQRLoginRequest: FlatBufferGeneratedTable {}
extension authv1_GenerateQRLoginResponse: FlatBufferGeneratedTable {}

extension authv1_ScanQRLoginRequest: FlatBufferGeneratedTable {}
extension authv1_ScanQRLoginResponse: FlatBufferGeneratedTable {}

extension authv1_ConfirmQRLoginRequest: FlatBufferGeneratedTable {}
extension authv1_ConfirmQRLoginResponse: FlatBufferGeneratedTable {}

extension authv1_RejectQRLoginRequest: FlatBufferGeneratedTable {}
extension authv1_RejectQRLoginResponse: FlatBufferGeneratedTable {}

extension authv1_QRLoginConfirmed: FlatBufferGeneratedTable {}
extension authv1_QRLoginExpiredOrRejected: FlatBufferGeneratedTable {}

extension authv1_WaitQRLoginResultRequest: FlatBufferGeneratedTable {}
extension authv1_QRLoginEvent: FlatBufferGeneratedTable {}