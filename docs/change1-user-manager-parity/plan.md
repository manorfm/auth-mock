# Change 1 - Plano de Evolucao

## Objetivo

Atualizar o `auth-mock` para simular o contrato HTTP atual do `user-manager-service`, priorizando compatibilidade de entrada/saida para consumidores.

## Estrategia

Manter a arquitetura simples do mock:

- Repositorios em memoria.
- Handlers finos.
- Validacoes suficientes para reproduzir comportamento esperado.
- Sem trazer Postgres, Redis, Vault ou RabbitMQ.

## Fase 1 - Modelo de usuario e respostas

1. Adicionar `CPF` e `Status` em `domain.User`.
2. Atualizar `CreateUserRequest` para aceitar `cpf`.
3. Atualizar registro client/management/admin para persistir `cpf`.
4. Criar DTO unico de resposta de usuario com:
   - `id`
   - `email`
   - `name`
   - `phone`
   - `cpf`
   - `user_type`
   - `allowed_channels`
   - `roles`
   - `status`
5. Ajustar `ListUsers`, `GetUser`, `GetMe`, `accounts/me` somente onde expõem usuario.

Risco: consumidores atuais podem esperar `email_verified`. Se existir uso conhecido, manter campo adicional temporario sem documenta-lo como contrato principal.

## Fase 2 - PATCH de usuario e alias `/me`

1. Trocar semantica interna de update para campos opcionais.
2. Adicionar `PATCH /api/users/{id}`.
3. Manter `PUT /api/users/{id}` como alias legado.
4. Adicionar `GET /api/me` apontando para `GetMeHandler`.
5. Validar que pelo menos um campo foi enviado em `PATCH`.

## Fase 3 - Staff identity

1. Criar `StaffIdentityService` em memoria ou metodo equivalente no `AuthService`.
2. Criar repositorio lookup por CPF normalizado.
3. Implementar `POST /api/admin/staff/ensure`.
4. Em novo CPF, criar usuario de gestao/standalone com:
   - `cpf`
   - `name`
   - `phone`
   - `email`, se informado
   - canal `management_panel`
   - status coerente com email informado/verificacao
5. Em CPF existente, atualizar nome, telefone e email conforme regras simples do mock.

Decisao recomendada para mock: se `email` estiver vazio, gerar email tecnico local apenas se o dominio exigir email obrigatorio internamente; nesse caso, nao expor esse email gerado em respostas se o real retornaria vazio.

## Fase 4 - Scoped roles

1. Criar dominio `ScopedRoleAssignment`.
2. Criar repositorio em memoria indexado por `user_id`.
3. Implementar:
   - `GET /api/admin/users/{id}/scoped-roles`
   - `POST /api/admin/users/{id}/scoped-roles`
   - `DELETE /api/admin/users/{id}/scoped-roles/{scopeType}/{scopeID}/{role}`
4. Validar `scope_type=restaurant`.
5. Validar roles `owner`, `manager`, `cashier`, `kitchen`.
6. `DELETE` deve marcar `status=revoked`, `revoked_at` e `revoked_by`, e responder `204`.

## Fase 5 - OAuth2 token endpoint

1. Criar decoder para `POST /oauth2/token` que aceite:
   - `application/json`
   - `application/x-www-form-urlencoded`
   - campos camelCase
   - campos snake_case
2. Adicionar parsing de `Authorization: Basic`.
3. Incluir `scope` no request.
4. Implementar grant `client_credentials` no `OIDCService`.
5. Gerar access token M2M com subject do client, roles M2M e audiences M2M.
6. Responder no formato OAuth2:
   - `access_token`
   - `token_type`
   - `expires_in`
   - `scope`
7. Ajustar grants `authorization_code` e `refresh_token` para responder `access_token` no body e refresh token em cookie.

## Fase 6 - OAuth2 client admin

1. Adicionar `M2MRoles` e `M2MAudiences` ao modelo de client em memoria.
2. Atualizar create/update/list/get de OAuth2 clients.
3. Validar campos obrigatorios quando `grant_types` contiver `client_credentials`.
4. Sem `client_credentials`, permitir arrays vazios.

## Fase 7 - TOTP

1. Adicionar estado pendente de TOTP em memoria.
2. Implementar `POST /api/totp/setup`.
3. Implementar `POST /api/totp/confirm`.
4. Implementar `POST /api/totp/backup-codes/regenerate`.
5. Alterar `POST /api/totp/disable` para exigir `{ "code": "..." }`.
6. Manter `POST /api/totp/enable` como alias legado.

## Fase 8 - Politicas de administracao

1. Manter `admin`/`root` como superusuarios.
2. Permitir roles `platform.*` como autorizacoes validas quando fizer sentido.
3. Nao bloquear o mock por ausencia de policy real se o usuario autenticado for `admin` ou `root`.

## Ordem recomendada

1. Fases 1 e 2: base de usuario.
2. Fases 3 e 4: integraçao com restaurant-manager via staff/scoped roles.
3. Fases 5 e 6: OAuth2 M2M e token endpoint.
4. Fase 7: TOTP novo.
5. Fase 8: refinamento de autorizacao.

## Validacao

Executar:

```bash
go test ./...
```

Adicionar testes de integracao HTTP para:

- `POST /api/admin/staff/ensure`
- fluxo ensure + assign scoped role + list + revoke
- `PATCH /api/users/{id}` com `cpf`
- `POST /api/oauth2/token` form-urlencoded com Basic Auth
- `POST /api/oauth2/token` `client_credentials`
- `POST /api/totp/setup` + `confirm`
- `POST /api/totp/backup-codes/regenerate`
