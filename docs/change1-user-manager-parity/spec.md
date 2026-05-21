# Change 1 - Paridade com user-manager-service

## Contexto

O `auth-mock` deve simular em memória a superfície HTTP atualmente exposta pelo `user-manager-service`, para que frontends e serviços consumidores possam testar integrações sem depender do serviço real.

Esta análise comparou:

- `user-manager-service/docs/http-api/openapi.yaml`
- `user-manager-service/docs/http-api/openapi-staff-management.yaml`
- `user-manager-service/internal/interfaces/http/router.go`
- handlers e modelos de domínio relevantes em `user-manager-service/internal/interfaces/http/handlers`
- rotas, handlers e domínio atuais em `auth-mock/internal`

## Gaps Encontrados

### 1. Staff identity

O `user-manager-service` expõe `POST /api/admin/staff/ensure`.

Entrada:

```json
{
  "name": "Funcionario",
  "phone": "85999999999",
  "email": "funcionario@example.com",
  "cpf": "12345678901"
}
```

Saida esperada:

```json
{
  "id": "01...",
  "email": "funcionario@example.com",
  "name": "Funcionario",
  "phone": "85999999999",
  "cpf": "12345678901"
}
```

Comportamento esperado:

- `cpf` e `name` obrigatorios.
- `phone` e `email` opcionais.
- Operacao idempotente por CPF.
- Se o CPF ja existir, atualizar dados basicos em vez de criar duplicata.
- Se `email` for informado para uma identidade de staff, manter o mesmo contrato do real para usuario pendente de vinculo/verificacao quando aplicavel.

Status no `auth-mock`: endpoint ausente.

### 2. Scoped roles por restaurante

O `user-manager-service` expõe:

- `GET /api/admin/users/{id}/scoped-roles`
- `POST /api/admin/users/{id}/scoped-roles`
- `DELETE /api/admin/users/{id}/scoped-roles/{scopeType}/{scopeID}/{role}`

Entrada do `POST`:

```json
{
  "scope_type": "restaurant",
  "scope_id": "restaurant-id",
  "role": "manager",
  "status": "active"
}
```

Saida do `POST` e do `GET`:

```json
{
  "id": "01...",
  "user_id": "01...",
  "scope_type": "restaurant",
  "scope_id": "restaurant-id",
  "role": "manager",
  "status": "active",
  "created_by": "01...",
  "revoked_by": null,
  "created_at": "2026-05-21T10:00:00Z",
  "updated_at": "2026-05-21T10:00:00Z",
  "revoked_at": null
}
```

Comportamento esperado:

- `scope_type` aceito inicialmente: `restaurant`.
- `role` aceitos: `owner`, `manager`, `cashier`, `kitchen`.
- `status` aceitos: `pending`, `active`, `revoked`; quando omitido, usar o default do serviço real.
- `DELETE` revoga o vinculo, nao apaga o usuario.
- O mock deve manter esses assignments em memoria por `user_id`.

Status no `auth-mock`: endpoints e modelo ausentes.

### 3. Perfil de usuario com CPF e status

O `user-manager-service` expõe `cpf` e `status` no modelo de usuario e nas respostas de registro/admin/staff/listagem.

Campos relevantes do real:

- `cpf`
- `status`: `active`, `email_verify`, `change_password`, `pending_email_link`
- `user_type`
- `allowed_channels`
- `roles`

Status no `auth-mock`:

- `cpf` ausente no dominio e nas entradas de cadastro.
- Existe `email_verified`, mas o contrato publico do real usa `status`.
- Algumas respostas do mock ja expõem `status`, mas derivado apenas de `email_verified`.

Requisito:

- Adicionar `CPF` ao dominio em memoria e aos DTOs de entrada/saida.
- Padronizar respostas publicas para expor `status` conforme contrato do real.
- Manter `email_verified` como detalhe interno ou compatibilidade apenas quando ja estiver exposto por algum consumidor conhecido.

### 4. Atualizacao parcial de usuario

O `user-manager-service` usa `PATCH /api/users/{id}` com semantica parcial.

Entrada:

```json
{
  "name": "Novo nome",
  "phone": "85988888888",
  "cpf": "12345678901"
}
```

Comportamento esperado:

- Pelo menos um campo deve ser enviado.
- Campos omitidos permanecem inalterados.
- `cpf` pode ser atualizado.
- A rota deve respeitar self-or-admin como no real.

Status no `auth-mock`:

- Existe `PUT /api/users/{id}`.
- `UpdateUserRequest` exige `name` e `phone`.
- `cpf` nao existe.

Requisito:

- Adicionar `PATCH /api/users/{id}`.
- Manter `PUT` como alias legado, se necessario, sem quebrar consumidores atuais.

### 5. `GET /api/me` como alias protegido

O `user-manager-service` registra `GET /api/me` para o usuario autenticado.

Status no `auth-mock`:

- Existe `GET /api/users/me`.
- `GET /api/me` ausente.

Requisito:

- Adicionar `GET /api/me` apontando para o mesmo handler de `GET /api/users/me`.
- Manter `GET /api/users/me` por compatibilidade local.

### 6. OAuth2 token endpoint

O `user-manager-service` evoluiu `POST /api/oauth2/token`.

Contrato atual:

- Aceita `application/json`.
- Aceita `application/x-www-form-urlencoded`.
- Aceita aliases camelCase e snake_case.
- Aceita credenciais via `Authorization: Basic` ou body.
- Suporta grants:
  - `authorization_code`
  - `refresh_token`
  - `client_credentials`
- Para `client_credentials`, retorna:

```json
{
  "access_token": "jwt",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile"
}
```

Status no `auth-mock`:

- Aceita apenas JSON.
- DTO usa camelCase.
- Nao implementa `client_credentials`.
- Retorna `TokenPair` completo no corpo em alguns fluxos, enquanto o real retorna apenas `access_token` e refresh em cookie para grants interativos.

Requisito:

- Implementar decoder JSON/form.
- Implementar Basic Auth para client credentials.
- Adicionar `scope` no request.
- Implementar grant `client_credentials` em memoria.
- Ajustar resposta de `authorization_code` e `refresh_token` para `{"access_token": "..."}` com refresh cookie, alinhado ao real.

### 7. OAuth2 client admin com M2M

O `user-manager-service` expõe `m2m_roles` e `m2m_audiences` no cadastro/edicao de clients OAuth2.

Entrada:

```json
{
  "id": "client-id",
  "secret": "secret",
  "redirect_uris": ["http://localhost/callback"],
  "grant_types": ["client_credentials"],
  "scopes": ["openid"],
  "m2m_roles": ["service"],
  "m2m_audiences": ["restaurant-manager-service"]
}
```

Status no `auth-mock`: campos ausentes.

Requisito:

- Adicionar campos ao modelo em memoria de OAuth2 client.
- Validar que `m2m_roles` e `m2m_audiences` sejam nao vazios quando `grant_types` contiver `client_credentials`.
- Usar esses campos na emissao do JWT M2M.

### 8. TOTP setup/confirm e backup code regeneration

O `user-manager-service` expõe novas rotas:

- `POST /api/totp/setup`
- `POST /api/totp/confirm`
- `POST /api/totp/backup-codes/regenerate`

Tambem manteve:

- `POST /api/totp/enable` como legado/deprecated.
- `POST /api/totp/disable` exigindo `code` no modo estrito.

Status no `auth-mock`:

- Existe `enable`, `verify`, `verify-backup`, `disable`.
- `setup`, `confirm` e `backup-codes/regenerate` ausentes.
- `disable` nao exige codigo.

Requisito:

- Implementar setup pendente + confirmacao.
- Retornar backup codes apenas no confirm/regenerate.
- Exigir codigo para disable, usando TOTP ou backup code.
- Manter `enable` como alias legado para setup, com headers de deprecacao se desejado.

### 9. Authorization/policies administrativas

O `user-manager-service` usa permissoes de plataforma:

- `platform.users.list`
- `platform.users.manage`
- `platform.staff.ensure`
- `platform.roles.manage`
- `platform.oauth.manage`
- `platform.standalone_users.manage`

Status no `auth-mock`:

- Admin usa regra simplificada por role `admin` ou `root` e canal `management_panel`.

Requisito:

- Como mock, nao precisa reproduzir todo motor de policy.
- Deve aceitar `admin`/`root` como superusuarios e, opcionalmente, aceitar roles com nomes de permissao `platform.*` para testar consumidores que enviam tokens mais proximos do real.

## Fora de escopo

- Persistencia em banco.
- Redis, Vault, criptografia at-rest e metricas Prometheus completas.
- RabbitMQ/eventos.
- Lockout MFA distribuido.
- Compatibilidade perfeita com codigos internos de erro, exceto onde consumidores dependam explicitamente deles.

## Criterios de aceite

1. O `auth-mock` disponibiliza todas as rotas listadas como ausentes nesta especificacao sob `API_BASE_PATH` padrao `/api`.
2. Os payloads de entrada aceitam os campos do `user-manager-service`.
3. As respostas principais possuem os mesmos campos publicos do real para usuarios, staff, scoped roles, OAuth2 token e TOTP.
4. A implementacao permanece em memoria.
5. Testes de handler ou integracao cobrem pelo menos os novos fluxos de staff, scoped roles, OAuth2 `client_credentials`, form-urlencoded token e TOTP setup/confirm.
