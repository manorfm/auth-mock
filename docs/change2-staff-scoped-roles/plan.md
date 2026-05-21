# Change 2 - Plano

## Objetivo

Registrar para implementacao futura a paridade do `auth-mock` com os fluxos de staff identity e scoped roles do `user-manager-service`.

## Plano Futuro

1. Criar lookup em memoria por CPF normalizado.
2. Criar handler/service para `POST /api/admin/staff/ensure`.
3. Criar modelo `ScopedRoleAssignment`.
4. Criar repositorio em memoria de scoped roles por `user_id`.
5. Registrar rotas administrativas de scoped roles.
6. Cobrir ensure, assign, list e revoke com testes HTTP.

## Dependencias

- O dominio de usuario ja deve possuir `cpf` e `status`.
- A autorizacao administrativa do mock deve aceitar `admin/root` e permissoes `platform.*`.
