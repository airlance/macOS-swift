// Wires each generated flatc table into FBMsg<T, Reader>. Names verified
// against real `flatc --swift --gen-object-api` output (flatc 25.12.19)
// — see MessageConformances.swift's header comment for the namespace
// casing note.

typealias LoginByGithubRequest = FBMsg<authv1_LoginByGithubRequestT, authv1_LoginByGithubRequest>
typealias LoginByGithubResponse = FBMsg<authv1_LoginByGithubResponseT, authv1_LoginByGithubResponse>

typealias ResumeSessionRequest = FBMsg<authv1_ResumeSessionRequestT, authv1_ResumeSessionRequest>
typealias ResumeSessionResponse = FBMsg<authv1_ResumeSessionResponseT, authv1_ResumeSessionResponse>

typealias TerminateSessionRequest = FBMsg<authv1_TerminateSessionRequestT, authv1_TerminateSessionRequest>
typealias TerminateSessionResponse = FBMsg<authv1_TerminateSessionResponseT, authv1_TerminateSessionResponse>

typealias ListSessionsRequest = FBMsg<authv1_ListSessionsRequestT, authv1_ListSessionsRequest>
typealias ListSessionsResponse = FBMsg<authv1_ListSessionsResponseT, authv1_ListSessionsResponse>

typealias KillSessionRequest = FBMsg<authv1_KillSessionRequestT, authv1_KillSessionRequest>
typealias KillSessionResponse = FBMsg<authv1_KillSessionResponseT, authv1_KillSessionResponse>

typealias SessionInfo = authv1_SessionInfoT // plain value type embedded in ListSessionsResponseT; no wire framing of its own

typealias GenerateQRLoginRequest = FBMsg<authv1_GenerateQRLoginRequestT, authv1_GenerateQRLoginRequest>
typealias GenerateQRLoginResponse = FBMsg<authv1_GenerateQRLoginResponseT, authv1_GenerateQRLoginResponse>

typealias ScanQRLoginRequest = FBMsg<authv1_ScanQRLoginRequestT, authv1_ScanQRLoginRequest>
typealias ScanQRLoginResponse = FBMsg<authv1_ScanQRLoginResponseT, authv1_ScanQRLoginResponse>

typealias ConfirmQRLoginRequest = FBMsg<authv1_ConfirmQRLoginRequestT, authv1_ConfirmQRLoginRequest>
typealias ConfirmQRLoginResponse = FBMsg<authv1_ConfirmQRLoginResponseT, authv1_ConfirmQRLoginResponse>

typealias RejectQRLoginRequest = FBMsg<authv1_RejectQRLoginRequestT, authv1_RejectQRLoginRequest>
typealias RejectQRLoginResponse = FBMsg<authv1_RejectQRLoginResponseT, authv1_RejectQRLoginResponse>

typealias WaitQRLoginResultRequest = FBMsg<authv1_WaitQRLoginResultRequestT, authv1_WaitQRLoginResultRequest>
typealias QRLoginEvent = FBMsg<authv1_QRLoginEventT, authv1_QRLoginEvent>

typealias ClientContext = authv1_ClientContextT // plain value type embedded in other T's; no wire framing of its own