# AGENTS.md

## Scope and Precedence
- **Scope:** This file applies to the entire repository unless a deeper `AGENTS.md` overrides parts of it.
- **Precedence:** System/developer/user instructions take priority over this file.
- **Goal:** Keep backend changes secure, predictable, and easy to review.

## Project Structure
- `src/app.module.ts`, `src/main.ts`
  - Application bootstrap, module wiring, global middleware/pipes, Swagger setup.
- `src/auth/`
  - Authentication flow (signup/login/refresh), JWT strategy/guard, auth DTOs and token helpers.
- `src/users/`
  - User entity and user persistence operations.
- `src/vaults/`
  - Vault CRUD, ownership checks, vault access guard, vault socket events.
- `src/notes/`
  - Note CRUD, note-level querying/filtering, note access guard, note socket events.
- `src/blocks/`
  - Block CRUD and ordering logic (`blocks-order.helper.ts`) for ordered note content.
- `src/batch/`
  - Batch command processing and event parsing/grouping for collaborative updates.
- `src/socket/`
  - Shared socket gateway/service utilities and room naming helpers.
- `migrations/`
  - TypeORM schema evolution history.
- `test/`
  - e2e test setup and integration specs.

## Main Concepts (Domain + Architecture)
1. **User-owned Vaults**
   - A user owns vaults; vault access is the root permission boundary.
2. **Vault contains Notes**
   - Notes belong to a vault and represent editable documents.
3. **Note contains ordered Blocks**
   - Blocks are ordered units of content inside notes; ordering is maintained server-side.
4. **JWT-based API auth**
   - HTTP routes rely on JWT guard; business authorization should be enforced in guards/services.
5. **Real-time collaboration via Socket.IO**
   - Vault and note rooms broadcast create/update/delete and batch events.
6. **Batch updates for conflict-sensitive operations**
   - Related edits can be grouped and executed in transaction scope via batch services.

## Coding and Review Rules
- Keep changes focused on one concern per commit.
- Prefer explicit TypeScript types over `any`.
- Keep DTO validation, guard logic, and service invariants aligned.
- For data integrity updates, include migration changes when schema changes.
- Avoid silent behavior changes; document any API contract changes in PR notes.

## Backend Quality Checklist (Before PR)
1. **Security/Access:** verify authentication + authorization boundaries are preserved.
2. **Data Integrity:** check entity relations, transactional behavior, and ordering logic.
3. **Validation:** ensure DTO/class-validator rules match controller/service expectations.
4. **Realtime Consistency:** confirm emitted socket events reflect persisted state.
5. **Observability:** prefer actionable errors and avoid leaking sensitive data.
6. **Tests:** add/update unit or e2e tests for changed behavior.
7. **PR Notes:** summarize change, rationale, risks, and follow-ups.
