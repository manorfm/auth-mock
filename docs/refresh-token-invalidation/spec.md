# Especificação: Invalidação de refresh token

## Contexto

O `user-manager-service` emite pares access + refresh (JWT). O access token tem vida curta; o refresh permite renovar sessão sem novo login. **Invalidar** o refresh de forma confiável é necessário para:

- logout explícito do usuário (“sair”);
- incidentes de segurança (senha alterada, conta comprometida, revogação administrativa);
- política de **rotação** que impeça reuso de um refresh já consumido;
- consistência entre **múltiplas instâncias** do mesmo serviço (escala horizontal).

## Estado atual (linha de base do repositório)

### O que já existe

1. **`POST /auth/refresh`** (`AuthService.RefreshToken`):
   - Valida o refresh via `JWTService.ValidateToken` (inclui checagem de **blacklist** por `jti`/ID do token).
   - **Adiciona o refresh apresentado à blacklist** (rotação: um refresh só serve para **uma** troca bem-sucedida).
   - Gera novo par de tokens.

2. **`JWTService`**: implementação em memória de blacklist (`tokenID -> expiração`), com limpeza periódica em goroutine.

3. **Resposta de erro**: `U0026` Token blacklisted quando um JWT (access ou refresh) validado está na blacklist.

### Lacunas identificadas

| Lacuna | Impacto |
|--------|--------|
| **OIDC `OIDCService.RefreshToken`** (`grant_type=refresh_token` em `/oauth2/token`) **não** chama `BlacklistToken` após validação | Permite **reuso** do mesmo refresh nesse fluxo; comportamento diferente de `/auth/refresh`. |
| **Blacklist só em memória** | Em **mais de uma réplica**, uma instância pode aceitar um refresh que outra já invalidou; revogação não é global. |
| **Sem endpoint de logout servidor-side** que invalide o refresh atual | Limpar cookie no browser ajuda, mas **não** revoga o JWT refresh se copiado; cliente precisa de invalidação explícita quando o produto exigir. |
| **Sem “revogar todas as sessões”** (opcional) | Troca de senha / admin não força novo login em todos os dispositivos por um mecanismo central de sessão. |

## Objetivos do trabalho

1. **Comportamento consistente**: qualquer caminho que troque refresh (BFF cookie ou OIDC) deve seguir a **mesma política de rotação + blacklist** (ou política documentada se OIDC for tratado diferente por decisão consciente).
2. **Invalidação explícita** (mínimo viável): permitir que o cliente solicite **logout** que marque o refresh atual como inválido no servidor (na medida do armazenamento escolhido).
3. **Preparar evolução multi-instância**: especificar armazenamento **externo** da blacklist ou equivalente (`session_version`, Redis, etc.) antes de escalar horizontalmente com garantias fortes.

## Requisitos funcionais

### RF1 — Rotação alinhada (OIDC)

- Ao processar `refresh_token` em `/oauth2/token`, o serviço deve **invalidar o refresh utilizado** da mesma forma que em `AuthService.RefreshToken` (blacklist do `jti` até `exp`), salvo decisão explícita documentada de não rotacionar (não recomendado).

### RF2 — Logout com invalidação

- Expor operação autenticada (ou baseada no refresh cookie, conforme desenho) que:
  - invalide o **refresh token atual** (e opcionalmente o access, se política exigir — ver notas);
  - limpe cookie de refresh onde aplicável (reuso do padrão atual `ClearRefreshTokenCookie`).

### RF3 — Erros e observabilidade

- Reuso de refresh já invalidado: resposta coerente (`U0026` ou código dedicado, documentado).
- Logs/métricas: contagem de refresh recusado por blacklist; sem vazar PII no log.

### RF4 — (Futuro) Revogação em larga escala

- Especificar (sem obrigar na primeira entrega) **versionamento de sessão** por usuário ou **família de refresh tokens** para invalidar todas as sessões num evento (troca de senha, admin).

## Requisitos não funcionais

- **RNF1**: Latência de verificação de blacklist compatível com o path de refresh (p95 alvo a definir no plano de carga).
- **RNF2**: TTL da entrada na blacklist alinhado ao `exp` do token (não guardar indefinidamente).
- **RNF3**: Solução distribuída deve evitar estado divergente prolongado entre réplicas (eventual consistency aceitável com limite documentado).

## Fora de escopo (primeira onda)

- Back-channel OIDC logout para RPs externos (campos discovery já mencionam `backchannel_logout_*` como opcionais futuros).
- Lista de dispositivos / UI de “encerrar outras sessões” (pode reutilizar RF4 depois).

## Critérios de aceite (onda 1)

1. Dois refresh seguidos com o **mesmo** token via fluxo OIDC falham na segunda tentativa com erro de token inválido/blacklisted (paridade com `/auth/refresh`).
2. `POST` de logout (rota acordada) remove cookie e impede reuso imediato do mesmo refresh **na mesma instância**.
3. Documentação atualizada: README + esta pasta SDD referenciando comportamento e limitações multi-instância enquanto blacklist for só in-process.

## Referências no código

- `internal/application/auth_service.go` — `RefreshToken` (rotação + blacklist).
- `internal/application/oidc_service.go` — `RefreshToken` (hoje sem blacklist).
- `internal/infrastructure/jwt/jwt_service.go` — `ValidateToken`, `BlacklistToken`, blacklist em memória.
- `internal/interfaces/http/handlers/handler_auth.go` — `RefreshTokenHandler` (cookie).
