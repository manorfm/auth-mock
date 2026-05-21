# Change 1 - Tasks

## A. Usuario e contrato publico

- [x] A1. Adicionar `CPF` e `Status` ao `domain.User`.
- [x] A2. Atualizar requests de registro para aceitar `cpf`.
- [x] A3. Atualizar resposta publica de usuario para incluir `cpf` e `status`.
- [x] A4. Ajustar registro client, management e standalone para persistir `cpf`.
- [x] A5. Atualizar listagem e consulta de usuarios para serializar o novo DTO.
- [x] A6. Garantir compatibilidade temporaria com campos legados somente onde necessario.

## B. Atualizacao parcial e aliases

- [x] B1. Criar request de PATCH com ponteiros/opcionais para `name`, `phone`, `cpf`.
- [x] B2. Alterar service/repository para update parcial.
- [x] B3. Registrar `PATCH /api/users/{id}`.
- [x] B4. Manter `PUT /api/users/{id}` como alias legado.
- [x] B5. Registrar `GET /api/me` como alias de usuario autenticado.
- [x] B6. Testar update parcial sem sobrescrever campos omitidos.

## C. Staff identity

Movido para `docs/change2-staff-scoped-roles` e nao implementado nesta rodada.

- [ ] C1. Criar lookup em memoria por CPF normalizado.
- [ ] C2. Criar service/handler para `EnsureStaffIdentity`.
- [ ] C3. Registrar `POST /api/admin/staff/ensure`.
- [ ] C4. Implementar criacao de staff por CPF.
- [ ] C5. Implementar atualizacao idempotente quando CPF ja existir.
- [ ] C6. Testar payload com email e sem email.

## D. Scoped roles

Movido para `docs/change2-staff-scoped-roles` e nao implementado nesta rodada.

- [ ] D1. Criar modelo `ScopedRoleAssignment`.
- [ ] D2. Criar repositorio em memoria de scoped roles.
- [ ] D3. Implementar `POST /api/admin/users/{id}/scoped-roles`.
- [ ] D4. Implementar `GET /api/admin/users/{id}/scoped-roles`.
- [ ] D5. Implementar `DELETE /api/admin/users/{id}/scoped-roles/{scopeType}/{scopeID}/{role}`.
- [ ] D6. Validar `scope_type`, `role` e `status`.
- [ ] D7. Testar assign, list e revoke.

## E. OAuth2 token endpoint

- [x] E1. Criar decoder JSON/form-urlencoded para `/oauth2/token`.
- [x] E2. Aceitar aliases camelCase e snake_case.
- [x] E3. Implementar leitura de credenciais via Basic Auth.
- [x] E4. Adicionar campo `scope` ao request.
- [x] E5. Implementar grant `client_credentials`.
- [x] E6. Ajustar resposta para `access_token`, `token_type`, `expires_in`, `scope` no M2M.
- [x] E7. Ajustar `authorization_code` e `refresh_token` para body `access_token` e refresh cookie.
- [x] E8. Testar JSON, form-urlencoded e Basic Auth.

## F. OAuth2 clients M2M

- [x] F1. Adicionar `m2m_roles` e `m2m_audiences` ao modelo de OAuth2 client.
- [x] F2. Atualizar create/update/get/list de clients.
- [x] F3. Validar obrigatoriedade dos campos M2M quando grant incluir `client_credentials`.
- [x] F4. Usar roles/audiences M2M ao emitir JWT de client credentials.
- [x] F5. Testar validacao de client M2M incompleto.

## G. TOTP

- [x] G1. Criar estado pendente de TOTP em memoria.
- [x] G2. Registrar e implementar `POST /api/totp/setup`.
- [x] G3. Registrar e implementar `POST /api/totp/confirm`.
- [x] G4. Registrar e implementar `POST /api/totp/backup-codes/regenerate`.
- [x] G5. Alterar `POST /api/totp/disable` para exigir codigo.
- [x] G6. Manter `POST /api/totp/enable` como alias legado.
- [x] G7. Testar setup, confirm, disable com codigo e regenerate.

## H. Autorizacao administrativa

- [x] H1. Manter `admin` e `root` com acesso total no mock.
- [x] H2. Permitir roles/permissoes `platform.*` para rotas administrativas equivalentes.
- [x] H3. Testar acesso admin legado e token com permissao `platform.staff.ensure`.

## I. Documentacao e verificacao

- [x] I1. Atualizar SDD do `auth-mock` com endpoints novos e separar staff/scoped roles no change2.
- [x] I2. Rodar `go test ./...`.
- [x] I3. Registrar gaps deliberadamente fora de escopo em nota tecnica, se algum item do spec nao for implementado.
