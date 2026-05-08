# Plano: Invalidação de refresh token

## Avaliação resumida do código

- **Rotação + blacklist** já implementados no fluxo **BFF** (`AuthService.RefreshToken` + cookie em `POST /auth/refresh`).
- **Gap crítico de segurança/consistência**: `OIDCService.RefreshToken` emite novo par **sem** colocar o refresh usado na blacklist — mesmo refresh pode ser reutilizado nesse grant até expirar naturalmente.
- **Blacklist in-process** (`jwtService`): adequado a **uma** réplica; insuficiente para HA sem camada compartilhada.
- **Logout servidor-side** inexistente: hoje não há `POST /auth/logout` que parseie o refresh do cookie e chame `BlacklistToken` antes de limpar o cookie.

## Sugestão de implementação (fases)

### Fase A — Correção de paridade OIDC (alta prioridade, baixo risco)

**Objetivo:** Mesma semântica de rotação que `AuthService.RefreshToken`.

**Ações:**

1. Em `OIDCService.RefreshToken`, após `ValidateToken` bem-sucedido e antes de gerar novo par:
   - validar `claims.ID` e `claims.ExpiresAt` (como em `AuthService`);
   - chamar `jwtService.BlacklistToken(claims.ID, claims.ExpiresAt.Time)`;
   - tratar falhas de blacklist como `ErrInternal` (espelhar auth).
2. Testes unitários em `oidc_service_test.go`: dois refresh com o mesmo token → segundo falha com blacklist/expirado.
3. Ajustar handlers/tests de `TokenHandler` se assumirem reuso de refresh.

**Risco:** baixo; alinha comportamento com RFC 6749 / boas práticas de refresh rotation.

---

### Fase B — Logout com invalidação de refresh (média prioridade)

**Objetivo:** Encerrar sessão “de verdade” para o refresh atual na instância que atende o pedido.

**Opções de desenho:**

| Opção | Prós | Contras |
|-------|------|--------|
| **B1 — `POST /auth/logout` só com cookie `refresh_token`** | Igual ao refresh: não exige access válido se o cliente só tem cookie; simples para SPAs mobile | Quem só tem access em header precisa passar refresh de outra forma ou chamar refresh antes |
| **B2 — Logout com `Authorization: Bearer` (access)** | Coerente com “usuário autenticado”; pode blacklistar o **access** `jti` (curta duração) e opcionalmente exigir body com refresh | Refresh órfão no storage de outro client até expirar |
| **B3 — B1 + B2** (aceitar um ou outro) | Melhor UX | Mais código e testes |

**Recomendação inicial:** **B1** alinhado ao `RefreshTokenHandler` (cookie), mais **opcional** body `refresh_token` para clientes que não usam cookie (mesmo padrão que outros endpoints).

**Ações:**

1. Novo handler `LogoutHandler`: ler refresh (cookie e/ou body) → `ValidateToken` → `BlacklistToken` → `ClearRefreshTokenCookie` → `204` ou `200` com body vazio.
2. Rota pública ou protegida? **Cookie-only logout** costuma ser **público** (CSRF: usar SameSite + método POST; avaliar double-submit se necessário).
3. Documentar que access token pode continuar válido até expirar (política comum); mitigação futura com access TTL curto ou denylist de access (mais pesado).

---

### Fase C — Blacklist distribuída / revogação global (médio-longo prazo)

**Quando:** antes ou junto com segunda réplica stateful do user-manager para auth.

**Opções:**

1. **Redis (SET com TTL = tempo até exp do token)** chave `blacklist:{jti}` — verificação O(1), TTL automático.
2. **`session_version` no `users`** (inteiro incrementado em troca de senha/admin) embedded nas claims do JWT — revoga **todos** tokens antigos sem listar JTIs (exige novo login após bump).
3. **Tabela `revoked_tokens`** — auditável; mais carga no Postgres; índice por `jti` + TTL/job de limpeza.

**Recomendação:** Redis para blacklist de **jti** (Fase A/B continuam iguais, só muda a implementação por trás de `JWTService` ou adapter `TokenRevocationStore`).

**Contrato interno sugerido:**

```text
type TokenRevocationStore interface {
  Revoke(ctx context.Context, jti string, expiresAt time.Time) error
  IsRevoked(ctx context.Context, jti string) (bool, error)
}
```

Implementação default in-memory; swap Redis em produção multi-réplica.

---

### Fase D — Revogar todas as sessões (opcional)

- Disparar `session_version++` em: reset de senha concluído, alteração de senha, ação admin “encerrar sessões”.
- `GenerateTokenPair` / `ValidateToken`: incluir claim `sv` e rejeitar se `sv` do token < `sv` do usuário (ler do banco ou cache).

Depende de migração e modelo de dados; encaixar após Fase C se o produto exigir.

## Dependências e riscos

- **CSRF** em logout por cookie: manter `SameSite`, POST-only; revisar CORS.
- **Observabilidade:** métrica `refresh_rejected_total{reason=blacklist}`.
- **Backward compatibility:** clientes OIDC que dependiam implicitamente de reuso de refresh **deixarão de funcionar** após Fase A — comportamento desejável; comunicar em changelog.

## Ordem sugerida de entrega

1. Fase A (+ testes + doc).
2. Fase B.
3. Fase C quando houver mais de uma instância ou requisito explícito de revogação global.
4. Fase D sob demanda.

## Referência cruzada

- Especificação detalhada: [spec.md](./spec.md)
- Tarefas rastreáveis: [tasks.md](./tasks.md)
