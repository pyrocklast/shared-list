import test from 'node:test';
import assert from 'node:assert/strict';
import { emptyDocument, operation, apply, field, sections, items, title, sectionFor } from '../web/model.js';
const L = '00000000-0000-4000-8000-000000000001', S = '00000000-0000-4000-8000-000000000002', I = '00000000-0000-4000-8000-000000000003';
const a = '00000000-0000-4000-8000-000000000004', b = '00000000-0000-4000-8000-000000000005';
function start() {
  const initial = operation(a, 1, [
    { entity: 'list', id: L, field: 'name', value: 'Groceries' },
    { entity: 'section', id: S, field: 'name', value: 'To buy' },
    { entity: 'section', id: S, field: 'position', value: 1000 },
    { entity: 'item', id: I, field: 'text', value: 'Milk' },
    { entity: 'item', id: I, field: 'sectionId', value: S },
    { entity: 'item', id: I, field: 'position', value: 1000 },
    { entity: 'item', id: I, field: 'checked', value: false },
  ]);
  return apply(emptyDocument(L), initial);
}
test('initial list, single unchecked section and items', () => {
  const d = start();
  assert.equal(title(d), 'Groceries');
  assert.deepEqual(sections(d).map(x => x.name), ['To buy']);
  assert.deepEqual(items(d).map(x => x.text), ['Milk']);
  assert.equal(items(d)[0].checked, false);
});
test('independent concurrent field changes converge in either order', () => {
  const first = operation(a, 2, [{ entity: 'item', id: I, field: 'checked', value: true }]);
  const second = operation(b, 2, [{ entity: 'item', id: I, field: 'text', value: 'Oat milk' }]);
  const left = apply(apply(start(), first), second);
  const right = apply(apply(start(), second), first);
  assert.deepEqual(left, right);
  assert.equal(items(left)[0].checked, true);
  assert.equal(items(left)[0].text, 'Oat milk');
  assert.equal(sectionFor(left, items(left)[0]), S);
});
test('concurrent rename of one field has stable device tie breaker', () => {
  const x = operation(a, 2, [{ entity: 'item', id: I, field: 'text', value: 'Tea' }]);
  const y = operation(b, 2, [{ entity: 'item', id: I, field: 'text', value: 'Coffee' }]);
  assert.deepEqual(apply(apply(start(), x), y), apply(apply(start(), y), x));
  assert.equal(items(apply(apply(start(), x), y))[0].text, 'Coffee');
});
test('deletion always wins; even later offline edits cannot resurrect the same id', () => {
  const d = operation(a, 2, [{ entity: 'item', id: I, field: 'deleted', value: true }]);
  const rename = operation(b, 999, [{ entity: 'item', id: I, field: 'text', value: 'Coffee' }]);
  const one = apply(apply(start(), rename), d);
  const two = apply(apply(start(), d), rename);
  assert.equal(items(one).length, 0);
  assert.deepEqual(one, two);
});
test('operations are idempotent, and section position is sortable', () => {
  const newSection = '00000000-0000-4000-8000-000000000006';
  const op = operation(a, 2, [
    { entity: 'section', id: newSection, field: 'name', value: 'Second hand' },
    { entity: 'section', id: newSection, field: 'position', value: 100 },
  ]);
  assert.deepEqual(apply(start(), op), apply(apply(start(), op), op));
  assert.deepEqual(sections(apply(start(), op)).map(s => s.name), ['Second hand', 'To buy']);
});
test('missing section falls back in projection without losing original sectionId', () => {
  const d = start();
  const gone = apply(d, operation(a, 2, [{ entity: 'section', id: S, field: 'deleted', value: true }]));
  assert.equal(sectionFor(gone, items(gone)[0]), undefined);
  assert.equal(field(gone.items[I], 'sectionId'), S);
});
test('invalid values and malformed operations are rejected', () => {
  assert.throws(() => operation(a, 2, [{ entity: 'item', id: I, field: 'text', value: '' }]));
  assert.throws(() => operation(a, 2, [{ entity: 'item', id: I, field: 'checked', value: 'yes' }]));
  assert.throws(() => operation(a, 2, [{ entity: 'item', id: '__proto__', field: 'text', value: 'Unsafe' }]));
  assert.throws(() => apply(start(), { v: 7, changes: [], clock: 2, device: a }));
});
