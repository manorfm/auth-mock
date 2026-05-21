# Change 2 - Staff identity e scoped roles

## Contexto

Este change guarda os dois pontos deliberadamente fora da implementacao atual do `auth-mock`:

- `POST /api/admin/staff/ensure`
- scoped roles por restaurante em `/api/admin/users/{id}/scoped-roles`

Eles existem no `user-manager-service`, mas nao serao implementados agora.

## Escopo Futuro

### Staff identity

Implementar `POST /api/admin/staff/ensure` com criacao/atualizacao idempotente por CPF.

Entrada:

```json
{
  "name": "Funcionario",
  "phone": "85999999999",
  "email": "funcionario@example.com",
  "cpf": "12345678901"
}
```

Saida:

```json
{
  "id": "01...",
  "email": "funcionario@example.com",
  "name": "Funcionario",
  "phone": "85999999999",
  "cpf": "12345678901"
}
```

### Scoped roles

Implementar:

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

Saida:

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

## Fora Desta Rodada

Nenhum handler, service, repository ou rota desses dois fluxos deve ser criado na implementacao atual.
