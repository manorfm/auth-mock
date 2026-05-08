# Especificação: Invalidação de refresh token

## Contexto

O `user-manager-service` emite pares access + refresh (JWT). O access token tem vida curta; o refresh permite renovar sessão sem novo login. **Invalidar** o refresh de forma confiável é necessário para:

- logout explícito do usuário (“sair”);
- incidentes de segurança (senha alterada, conta comprometida, revogação administrativa);
- política de **rotação** que impeça reuso de um refresh já consumido;
- consistência entre **múltiplas instâncias** do mesmo serviço (escala horizontal).

## Estado atual (implementado neste repositório)

### O que já existe

1. **`POST {API_BASE_PATH}/auth/refresh`** (`AuthService.RefreshWithRefreshToken` + `RefreshTokenHandler`):
   - Valida o refresh via `JWTService.ValidateToken` (inclui checagem de **blacklist** por `jti`).
   - **Adiciona o refresh apresentado à blacklist** (rotação: um refresh só serve para **uma** troca bem-sucedida).
   - Gera novo par de tokens e regrava o cookie de refresh quando aplicável.

2. **`POST {API_BASE_PATH}/oauth2/token`** com `grant_type=refresh_token` (`OIDCService.RefreshToken`):
   - Mesma política de rotação + blacklist que o item acima.
   - Reuso do mesmo refresh após troca bem-sucedida: resposta **`U0026` Token blacklisted** (HTTP `400`), alinhada ao handler.

3. **`POST {API_BASE_PATH}/auth/logout`** (`AuthService.LogoutWithRefreshToken`):
   - Lê refresh do cookie ou do body JSON (`refresh_token`), valida, blacklista o `jti`, limpa cookie, **`204 No Content`**.

4. **`JWTService`**: revogação via `TokenRevocationStore` — **somente em memória** neste repositório (TTL até `exp` do token na store).

5. **Código de erro**: `U0026` quando o JWT validado está na blacklist (access ou refresh).

### Lacunas / próximos passos

| Item | Impacto |
|------|--------|
| **Multi-réplica** | Blacklist de `jti` é **por processo**. Escalar horizontalmente sem sticky sessions implica aceitar que um refresh invalidado em uma instância pode ainda ser aceito em outra até expirar — **fora do escopo** deste mock (sem backend compartilhado). |
| **Observabilidade** | Métrica dedicada `refresh_rejected_total{reason=blacklist}` ainda não implementada (RF3). |

## Objetivos do trabalho

1. **Comportamento consistente**: qualquer caminho que troque refresh (BFF cookie ou OIDC) deve seguir a **mesma política de rotação + blacklist** (ou política documentada se OIDC for tratado diferente por decisão consciente).
2. **Invalidação explícita** (mínimo viável): permitir que o cliente solicite **logout** que marque o refresh atual como inválido no servidor (na medida do armazenamento escolhido).
3. **Revogar todas as sessões**: `session_version` + claim `sv` em JWT; bump na troca de senha invalida tokens antigos (`U0069`).

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

### RF4 — Revogação em larga escala (sessão)

- **Implementado:** `session_version` no usuário, claim **`sv`** nos JWTs, bump na troca de senha → tokens anteriores falham com **`U0069`**.

## Requisitos não funcionais

- **RNF1**: Latência de verificação de blacklist compatível com o path de refresh (p95 alvo a definir no plano de carga).
- **RNF2**: TTL da entrada na blacklist alinhado ao `exp` do token (não guardar indefinidamente).
- **RNF3**: Este mock **não** oferece blacklist compartilhada entre processos; multi-réplica com garantia forte de revogação de `jti` ficaria para outro serviço ou camada.

## Fora de escopo (primeira onda)

- Back-channel OIDC logout para RPs externos (campos discovery já mencionam `backchannel_logout_*` como opcionais futuros).
- Lista de dispositivos / UI de “encerrar outras sessões” (pode reutilizar RF4 depois).

## Critérios de aceite (onda 1)

1. Dois refresh seguidos com o **mesmo** token via fluxo OIDC falham na segunda tentativa com erro de token inválido/blacklisted (paridade com `/auth/refresh`).
2. `POST` de logout (rota acordada) remove cookie e impede reuso imediato do mesmo refresh **na mesma instância**.
3. Documentação atualizada: README + esta pasta SDD referenciando comportamento e que a blacklist é **só in-process** neste serviço.

## Referências no código

- `internal/application/auth_service.go` — `RefreshWithRefreshToken`, `LogoutWithRefreshToken` (rotação + blacklist).
- `internal/application/oidc_service.go` — `RefreshToken` (rotação + blacklist).
- `internal/domain/jwt.go` — `TokenRevocationStore` (contrato de revogação).
- `internal/infrastructure/jwt/memory_revocation_store.go` — implementação em memória (única neste repo).
- `internal/infrastructure/jwt/jwt_service.go` — `ValidateToken`, `BlacklistToken`; delega revogação ao `TokenRevocationStore`; `NewJWTService` instancia a store em memória.
- `internal/interfaces/http/handlers/handler_auth.go` — `RefreshTokenHandler`, `LogoutHandler`.
- `internal/interfaces/http/handlers/handler_oidc.go` — `TokenHandler` (`grant_type=refresh_token`, erro `U0026` quando aplicável).
