# Phase-1 acceptance checklist

## Automated checks performed

- `npm test`: field merge, concurrent independent edits, deterministic tie-breaking, deletion tombstones, sections, malformed-operation rejection.
- `npm test`: AES-GCM round trips, unique IVs, context binding and tampering rejection.
- Syntax checks with `node --check` for all JavaScript sources.
- Manifest and service-worker asset path consistency checked.

## Browser checks still required

The development environment's managed Chromium policy blocks navigation to local URLs, preventing an actual browser E2E run here. These cases have **not been claimed as passing**:

1. Chrome Android, Safari iOS, Firefox desktop, Chrome desktop: create and rename several lists; reopen after browser restart.
2. Create/rename/reorder/delete-empty sections; verify nonempty sections cannot be deleted.
3. Add/edit/move/check/uncheck/delete items; completed items return to the section they came from.
4. Open the PWA online once, close, enable airplane mode, reopen and edit; then reload offline.
5. Open two browser tabs on one origin and edit simultaneously; verify no lost entries.
6. Check several adjacent items rapidly; ensure the list does not jump during the short settle period.
7. Force IndexedDB quota/storage failure; verify no success message appears for a failed write.
8. Test keyboard, screen reader focus order, reduced motion, 200% font scaling, light and dark themes.
9. Inspect IndexedDB: no item names in `documents` or `outbox`; confirm key in `keys` remains extractable and do **not** mistake this for a protected local vault.

**Not part of phase 1:** actual multi-device realtime synchronization, server encryption, QR admission and recovery. A browser smoke test on these cannot pass until later phases exist.
