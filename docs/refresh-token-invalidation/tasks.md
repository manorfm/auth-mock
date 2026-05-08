# Tarefas: Invalidação de refresh token (SDD)

Legenda: `[ ]` pendente · `[x]` feito (atualizar ao implementar)

## Fase A — Paridade OIDC + rotação

- [x] **A1.** Revisar `OIDCService.RefreshToken` e espelhar pós-validação de `AuthService.RefreshToken` (blacklist do `jti` do refresh apresentado; checagem de `claims.ID` / `ExpiresAt`).
- [x] **A2.** Unificar tratamento de erro (`ErrInvalidToken`, `ErrTokenBlacklisted`, etc.) com o handler `/oauth2/token` — resposta OAuth2 coerente em falha de reuso.
- [x] **A3.** Testes unitários: primeiro refresh OK; segundo com mesmo string → erro (blacklist ou equivalente).
- [x] **A4.** Revisar `handler_oidc_test.go` / integração que mocke `RefreshToken` — expectativas de cookie e corpo alinhadas à rotação.
- [x] **A5.** Atualizar CHANGELOG / README (link para SDD) mencionando mudança de comportamento OIDC refresh.

## Fase B — Logout servidor-side

- [x] **B1.** Decidir contrato final: cookie-only vs cookie + body opcional (ver [plan.md](./plan.md)).
- [x] **B2.** Implementar `POST {API_BASE_PATH}/auth/logout` (nome final a confirmar): parse refresh → `ValidateToken` → `BlacklistToken` → `ClearRefreshTokenCookie`; status HTTP documentado.
- [x] **B3.** Registrar rota em `router.go` (grupo público ou autenticado conforme desenho).
- [x] **B4.** Testes de handler: logout com cookie válido → cookie limpo + refresh inválido na próxima chamada **na mesma instância**.
- [x] **B5.** Revisão de segurança: SameSite, CSRF, CORS (skill auth-hardening se aplicável).

## Fase C — Contrato de revogação (escopo deste repo: só memória)

- [x] **C1.** ADR / plano: neste mock, blacklist **apenas in-process** (sem datastore externo).
- [x] **C2.** Interface `TokenRevocationStore` e `jwtService` delegando `BlacklistToken` / `IsTokenBlacklisted`.
- [x] **C3.** Implementação em memória com TTL alinhado ao `exp` do token (`MemoryTokenRevocationStore`).
- [x] **C4.** Sem configuração de URL externa — `NewJWTService` sempre usa memória.
- [x] **C5.** Testes unitários da store em memória e fluxos refresh/logout.

## Fase D — Revogar todas as sessões (opcional)

- [x] **D1.** Modelar `session_version` (migração `users` ou tabela auxiliar).
- [x] **D2.** Incluir claim nas emissões de access/refresh; validar em `ValidateToken` ou middleware.
- [x] **D3.** Incrementar versão em troca de senha / fluxo admin documentado.
- [x] **D4.** Testes de regressão: após bump, tokens antigos falham.

## Documentação

- [x] **DOC1.** Manter [spec.md](./spec.md), [plan.md](./plan.md) e este arquivo sincronizados com o código após cada fase.
- [x] **DOC2.** README: seção “Sessões e refresh tokens” + link `docs/refresh-token-invalidation/`.
