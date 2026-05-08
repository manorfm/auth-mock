# ADR: Onde armazenar revogação de tokens (blacklist / rotação)

**Status:** Accepted — **in-memory only** neste repositório (`auth-mock`)

**Contexto**

A rotação de refresh invalida o `jti` do token usado. O serviço precisa de um lugar para guardar JTIs revogados até o `exp` natural do JWT.

**Decisão**

- **Este mock:** usar **exclusivamente** `MemoryTokenRevocationStore` dentro do processo. Não há variáveis de ambiente nem cliente Redis (ou outro datastore) para revogação.
- **Multi-réplica:** não é objetivo deste repo. Cada instância tem sua própria blacklist; documentar a limitação em README / `spec.md`.
- **Invalidar todas as sessões** (ex.: após troca de senha): usar **`session_version`** + claim **`sv`** nos JWTs (ver Fase D), independentemente da blacklist por `jti`.

**Consequências**

- `domain.TokenRevocationStore` + `MemoryTokenRevocationStore`; `NewJWTService` sempre compõe a store em memória.
- `docker-compose` não inclui serviço Redis para este fim.
- Produtos reais que exijam blacklist **compartilhada** entre instâncias devem implementar outro adapter fora deste projeto ou em um fork, mantendo o mesmo contrato de interface se desejado.
