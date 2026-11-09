// Deterministic field-register model. No DOM, storage, or network dependencies.
export const VERSION = 1;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const allowed = {
  list: { name: 'string' },
  section: { name: 'string', position: 'number', deleted: 'boolean' },
  item: { text: 'string', sectionId: 'string', position: 'number', checked: 'boolean', deleted: 'boolean' },
};
export function id() { return crypto.randomUUID(); }
export function emptyDocument(listId) {
  if (!UUID.test(listId)) throw Error('Invalid list ID');
  return { v: VERSION, id: listId, clock: 0, list: {}, sections: {}, items: {} };
}
export function field(entity, name, fallback = undefined) {
  return entity?.[name]?.value ?? fallback;
}
function newer(a, b) {
  return !b || a.clock > b.clock || (a.clock === b.clock && a.device > b.device);
}
function validateChange(change) {
  if (!change || !allowed[change.entity]?.[change.field]) throw Error('Invalid change');
  const kind = allowed[change.entity][change.field];
  if (typeof change.value !== kind || (kind === 'number' && (!Number.isSafeInteger(change.value) || Math.abs(change.value) > 1e9))) throw Error('Invalid field type');
  if (kind === 'string') {
    const cap = change.field === 'text' ? 160 : change.field === 'name' ? 80 : 100;
    if (!change.value.trim() || change.value.length > cap) throw Error('Invalid text');
  }
  if (!UUID.test(change.id)) throw Error('Invalid entity ID');
}
export function operation(device, clock, changes) {
  if (!Number.isSafeInteger(clock) || clock < 1 || !UUID.test(device) || !Array.isArray(changes) || changes.length < 1 || changes.length > 32) throw Error('Invalid operation');
  changes.forEach(validateChange);
  return { v: VERSION, id: id(), device, clock, changes };
}
export function apply(doc, op) {
  if (doc.v !== VERSION || op.v !== VERSION || !UUID.test(doc.id) || !UUID.test(op.id) || !UUID.test(op.device) || !Number.isSafeInteger(op.clock) || op.clock < 1 || !Array.isArray(op.changes) || !op.changes.length || op.changes.length > 32) throw Error('Unsupported operation');
  const result = structuredClone(doc);
  for (const change of op.changes) {
    validateChange(change);
    if (change.entity === 'list' && change.id !== result.id) throw Error('Wrong list');
    const scope = change.entity === 'list' ? null : change.entity === 'section' ? result.sections : result.items;
    const target = scope ? (scope[change.id] ||= {}) : result.list;
    // A deletion is irreversible for this entity ID; recreating needs a fresh ID.
    const proposed = { value: change.value, clock: op.clock, device: op.device };
    if (change.field === 'deleted' && change.value === true) {
      // Keep only the tombstone. Either arrival order converges to the same state.
      if (newer(proposed, target.deleted)) {
        if (scope) scope[change.id] = { deleted: proposed };
      }
    } else if (field(target, 'deleted') !== true && newer(proposed, target[change.field])) {
      target[change.field] = proposed;
    }
  }
  result.clock = Math.max(result.clock, op.clock);
  return result;
}
export function sections(doc) {
  return Object.entries(doc.sections)
    .filter(([, s]) => field(s, 'deleted', false) !== true)
    .map(([key, s]) => ({ id: key, name: field(s, 'name', ''), position: field(s, 'position', 0) }))
    .sort((a, b) => a.position - b.position || a.id.localeCompare(b.id));
}
export function items(doc) {
  return Object.entries(doc.items)
    .filter(([, it]) => field(it, 'deleted', false) !== true)
    .map(([key, it]) => ({ id: key, text: field(it, 'text', ''), sectionId: field(it, 'sectionId', ''), checked: field(it, 'checked', false), position: field(it, 'position', 0) }))
    .filter(it => it.text)
    .sort((a, b) => a.position - b.position || a.id.localeCompare(b.id));
}
export function title(doc) { return field(doc.list, 'name', ''); }
export function sectionFor(doc, item) {
  return sections(doc).some(s => s.id === item.sectionId) ? item.sectionId : sections(doc)[0]?.id;
}
