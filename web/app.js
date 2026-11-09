import { id, field, title, sections, items, sectionFor } from './model.js';
import * as db from './db.js';
import { t, language } from './i18n.js';

document.documentElement.lang = language;
const root = document.querySelector('#app');
const notice = document.querySelector('#notice');
let activeId = sessionStorage.getItem('shared-list-active') || null;
let current = null;
let completedOpen = false;
let renderVersion = 0;
const drafts = new Map();
const settling = new Set();
let settleTimer;

function node(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (name === 'class') e.className = value;
    else if (name === 'text') e.textContent = String(value);
    else if (name === 'value') e.value = value;
    else if (name === 'checked') e.checked = value;
    else if (name === 'disabled') e.disabled = value;
    else if (name.startsWith('on') && typeof value === 'function') e.addEventListener(name.slice(2).toLowerCase(), value);
    else e.setAttribute(name, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) if (child != null && child !== false) e.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return e;
}
const button = (label, attrs = {}, ...children) => node('button', { type: 'button', ...attrs }, ...children.length ? children : [label]);
function fail(err) {
  console.error(err);
  notice.textContent = err?.message || t('storageError');
  notice.hidden = false;
  clearTimeout(fail.timer);
  fail.timer = setTimeout(() => notice.hidden = true, 6000);
}
async function action(fn) {
  try { await fn(); await render(); } catch (err) { settling.clear(); fail(err); await render(); }
}
function header(titleText, listMode = false) {
  const nav = node('header', { class: 'topbar' });
  const left = node('div', { class: 'topbar-left' });
  if (listMode) left.append(button('←', { class: 'back', 'aria-label': t('goBack'), onclick: () => { activeId = null; sessionStorage.removeItem('shared-list-active'); current = null; render(); } }));
  else left.append(node('span', { class: 'brand-mark', 'aria-hidden': 'true' }, '✓'));
  left.append(node('span', { class: listMode ? 'eyebrow' : 'brand-name' }, listMode ? t('yourLists') : t('app')));
  nav.append(left);
  if (listMode) nav.append(button('···', { class: 'icon-button', 'aria-label': t('listMenu'), onclick: listOptions }));
  return [nav, node('h1', { class: 'page-title', text: titleText })];
}
function dialogBase(heading) {
  const dialog = node('dialog', { class: 'editor' });
  dialog.append(node('h2', { text: heading }));
  document.body.append(dialog);
  dialog.addEventListener('close', () => dialog.remove(), { once: true });
  dialog.addEventListener('click', e => { if (e.target === dialog) dialog.close(); });
  return dialog;
}
function fieldDialog({ heading, label, initial = '', maxLength = 80, confirm = t('save'), save }) {
  const d = dialogBase(heading);
  const form = node('form', { class: 'editor-form' });
  const inputId = `field-${id()}`;
  const input = node('input', { id: inputId, required: true, maxlength: maxLength, value: initial, autocomplete: 'off' });
  const error = node('p', { class: 'form-error', role: 'alert' });
  const controls = node('div', { class: 'dialog-actions' },
    button(t('cancel'), { class: 'quiet', onclick: () => d.close() }),
    node('button', { type: 'submit', class: 'primary' }, confirm));
  form.append(node('label', { for: inputId, text: label }), input, error, controls);
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const value = input.value.trim();
    if (!value) { error.textContent = t('invalidName'); input.focus(); return; }
    const submit = form.querySelector('[type=submit]'); submit.disabled = true;
    try { await save(value); d.close(); await render(); }
    catch (err) { error.textContent = err.message || t('storageError'); submit.disabled = false; }
  });
  d.append(form);
  d.showModal();
  input.focus(); input.select();
}
function confirmDialog({ heading, detail, onConfirm }) {
  const d = dialogBase(heading);
  const form = node('form', { class: 'editor-form' }, node('p', { class: 'muted', text: detail }));
  form.append(node('div', { class: 'dialog-actions' },
    button(t('cancel'), { class: 'quiet', onclick: () => d.close() }),
    button(t('delete'), { class: 'danger', onclick: async () => { try { await onConfirm(); d.close(); await render(); } catch (err) { fail(err); } } })));
  d.append(form); d.showModal();
}
function showLists(entries) {
  const shell = node('main', { class: 'shell' }, header(t('yourLists')));
  const top = node('div', { class: 'heading-row' }, node('p', { class: 'subline', text: t('details') }),
    button(`＋ ${t('createList')}`, { class: 'primary', onclick: () => fieldDialog({
      heading: t('newList'), label: t('listName'), confirm: t('create'),
      save: async name => { activeId = await db.createList(name, t('toBuy')); sessionStorage.setItem('shared-list-active', activeId); },
    }) }));
  shell.append(top);
  if (!entries.length) shell.append(node('div', { class: 'empty-state' }, node('p', { text: t('firstList') })));
  else {
    const list = node('ul', { class: 'list-catalog' });
    for (const { document: doc } of entries) {
      const count = items(doc).filter(it => !it.checked).length;
      const label = `${title(doc)}${count ? ' · ' + count : ''}`;
      const row = node('li', {}, button(label, { class: 'list-tile', onclick: () => { activeId = doc.id; sessionStorage.setItem('shared-list-active', activeId); render(); } },
        node('span', { class: 'tile-title', text: title(doc) }),
        node('span', { class: 'tile-aside' }, String(count), ' ›')));
      list.append(row);
    }
    shell.append(list);
  }
  shell.append(node('p', { class: 'local-caption', text: t('localOnly') }));
  return shell;
}
function listOptions() {
  if (!current) return;
  const d = dialogBase(t('listMenu'));
  const actions = node('div', { class: 'stack-actions' },
    button(t('rename'), { onclick: () => { d.close(); fieldDialog({ heading: t('rename'), label: t('listName'), initial: title(current), save: value => db.changeList(current.id, [{ entity: 'list', id: current.id, field: 'name', value }]) }); } }),
    button(t('deleteList'), { class: 'danger-text', onclick: () => { d.close(); confirmDialog({ heading: t('confirmDelete'), detail: t('deleteListDetail'), onConfirm: async () => { await db.deleteList(current.id); activeId = null; current = null; sessionStorage.removeItem('shared-list-active'); } }); } }),
    button(t('cancel'), { class: 'quiet', onclick: () => d.close() }));
  d.append(actions); d.showModal();
}
function sectionOptions(sectionId) {
  const doc = current;
  if (!doc) return;
  const all = sections(doc);
  const target = all.find(s => s.id === sectionId);
  const index = all.findIndex(s => s.id === sectionId);
  if (!target) return;
  const d = dialogBase(t('editSection'));
  const box = node('div', { class: 'stack-actions' });
  box.append(button(t('edit'), { onclick: () => { d.close(); fieldDialog({ heading: t('editSection'), label: t('sectionName'), initial: target.name, save: name => db.changeList(doc.id, [{ entity: 'section', id: target.id, field: 'name', value: name }]) }); } }));
  const move = delta => action(async () => {
    const fresh = await db.loadList(doc.id);
    const arr = sections(fresh); const at = arr.findIndex(s => s.id === target.id); const other = arr[at + delta];
    if (!other) return;
    await db.changeList(doc.id, [
      { entity: 'section', id: target.id, field: 'position', value: other.position },
      { entity: 'section', id: other.id, field: 'position', value: arr[at].position },
    ]);
  });
  if (index > 0) box.append(button(t('moveUp'), { onclick: () => { d.close(); move(-1); } }));
  if (index < all.length - 1) box.append(button(t('moveDown'), { onclick: () => { d.close(); move(1); } }));
  if (all.length > 1) box.append(button(t('deleteSection'), { class: 'danger-text', onclick: () => {
    if (items(current).some(it => it.sectionId === sectionId)) { fail(new Error(t('sectionNotEmpty'))); return; }
    d.close(); confirmDialog({ heading: t('deleteSection'), detail: target.name, onConfirm: () => db.changeList(doc.id, [{ entity: 'section', id: target.id, field: 'deleted', value: true }]) });
  } }));
  box.append(button(t('cancel'), { class: 'quiet', onclick: () => d.close() }));
  d.append(box); d.showModal();
}
function editItem(itemId) {
  const doc = current;
  const item = items(doc).find(it => it.id === itemId);
  if (!item) return;
  const d = dialogBase(t('editItem'));
  const form = node('form', { class: 'editor-form' });
  const input = node('input', { id: 'edit-item-name', value: item.text, required: true, maxlength: 160 });
  const select = node('select', { id: 'edit-item-section' });
  for (const s of sections(doc)) select.append(node('option', { value: s.id, text: s.name }));
  select.value = sectionFor(doc, item) || '';
  const error = node('p', { class: 'form-error', role: 'alert' });
  const controls = node('div', { class: 'dialog-actions' },
    button(t('deleteItem'), { class: 'danger-text', onclick: async () => { try { await db.changeList(doc.id, [{ entity: 'item', id: item.id, field: 'deleted', value: true }]); d.close(); await render(); } catch (e) { error.textContent = e.message; } } }),
    button(t('cancel'), { class: 'quiet', onclick: () => d.close() }),
    node('button', { type: 'submit', class: 'primary' }, t('save')));
  form.append(node('label', { for: 'edit-item-name', text: t('itemName') }), input,
    node('label', { for: 'edit-item-section', text: t('moveTo') }), select, error, controls);
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const text = input.value.trim(); if (!text) { error.textContent = t('invalidName'); return; }
    const changes = [];
    if (text !== item.text) changes.push({ entity: 'item', id: item.id, field: 'text', value: text });
    if (select.value !== item.sectionId) changes.push({ entity: 'item', id: item.id, field: 'sectionId', value: select.value });
    if (!changes.length) { d.close(); return; }
    try { await db.changeList(doc.id, changes); d.close(); await render(); }
    catch (e) { error.textContent = e.message || t('storageError'); }
  });
  d.append(form); d.showModal(); input.focus();
}
function toggleItem(doc, item) {
  const checked = !item.checked;
  if (checked) settling.add(item.id);
  else settling.delete(item.id);
  action(async () => {
    await db.changeList(doc.id, [{ entity: 'item', id: item.id, field: 'checked', value: checked }]);
    if (checked) {
      clearTimeout(settleTimer);
      settleTimer = setTimeout(() => { settling.clear(); render(); }, 900);
    }
  });
}
function itemRow(doc, item) {
  const itemLabel = node('span', { class: 'item-label', text: item.text });
  const check = node('input', { type: 'checkbox', class: 'item-check', checked: item.checked,
    'aria-label': `${item.checked ? t('uncheck') : t('check')}: ${item.text}`,
    onchange: () => toggleItem(doc, item) });
  return node('li', { class: item.checked ? 'item-row checked' : 'item-row' }, check,
    button(item.text, { class: 'item-text', onclick: () => editItem(item.id), 'aria-label': `${t('editItem')}: ${item.text}` }, itemLabel));
}
function addRow(doc, section) {
  const form = node('form', { class: 'add-row' });
  const input = node('input', { type: 'text', class: 'add-input', placeholder: t('addItem'),
    'aria-label': `${t('addItem')} — ${section.name}`, maxlength: 160, autocomplete: 'off', value: drafts.get(section.id) || '',
    'data-add-section': section.id, oninput: e => drafts.set(section.id, e.target.value) });
  const add = node('button', { type: 'submit', class: 'add-button', 'aria-label': `${t('addItem')} — ${section.name}` }, '+');
  form.append(input, add);
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const value = input.value.trim(); if (!value) return;
    add.disabled = true;
    try {
      const fresh = await db.loadList(doc.id);
      const positions = items(fresh).filter(it => it.sectionId === section.id).map(it => it.position);
      const newItemId = id();
      await db.changeList(doc.id, [
        { entity: 'item', id: newItemId, field: 'text', value },
        { entity: 'item', id: newItemId, field: 'sectionId', value: section.id },
        { entity: 'item', id: newItemId, field: 'position', value: Math.min(1e9, Math.max(0, ...positions) + 1000) },
        { entity: 'item', id: newItemId, field: 'checked', value: false },
      ]);
      drafts.delete(section.id);
      await render();
      root.querySelector(`[data-add-section="${section.id}"]`)?.focus();
    } catch (err) { fail(err); add.disabled = false; }
  });
  return form;
}
function showList(doc) {
  const shell = node('main', { class: 'shell' }, header(title(doc), true));
  const activeItems = items(doc);
  for (const section of sections(doc)) {
    const wrapper = node('section', { class: 'section' });
    const h = node('div', { class: 'section-heading' }, node('h2', { text: section.name }),
      button('···', { class: 'icon-button section-menu', 'aria-label': `${t('editSection')}: ${section.name}`, onclick: () => sectionOptions(section.id) }));
    const rows = node('ul', { class: 'items' });
    for (const item of activeItems.filter(i => (!i.checked || settling.has(i.id)) && sectionFor(doc, i) === section.id)) rows.append(itemRow(doc, item));
    wrapper.append(h, rows, addRow(doc, section));
    shell.append(wrapper);
  }
  shell.append(button(`＋ ${t('newSection')}`, { class: 'add-section', onclick: () => fieldDialog({
    heading: t('newSection'), label: t('sectionName'), confirm: t('create'),
    save: async name => {
      const fresh = await db.loadList(doc.id);
      const pos = Math.max(0, ...sections(fresh).map(s => s.position)) + 1000;
      const sid = id();
      await db.changeList(doc.id, [
        { entity: 'section', id: sid, field: 'name', value: name },
        { entity: 'section', id: sid, field: 'position', value: pos },
      ]);
    },
  }) }));
  const complete = activeItems.filter(it => it.checked);
  const completed = node('section', { class: 'completed-section' });
  completed.append(button(`${t('completed')} (${complete.length})`, {
    class: 'completed-toggle', 'aria-expanded': String(completedOpen),
    'aria-label': `${completedOpen ? t('hideCompleted') : t('showCompleted')} (${complete.length})`,
    onclick: () => { completedOpen = !completedOpen; render(); },
  }, node('span', {}, `${completedOpen ? '⌄' : '›'} ${t('completed')}`), node('span', { class: 'completed-count', text: String(complete.length) })));
  if (completedOpen) {
    const rows = node('ul', { class: 'items completed-items' });
    for (const item of complete.filter(it => !settling.has(it.id))) rows.append(itemRow(doc, item));
    completed.append(rows);
  }
  shell.append(completed, node('p', { class: 'local-caption', text: t('local') }));
  return shell;
}
async function render() {
  const version = ++renderVersion;
  const previousY = window.scrollY;
  const focusedSection = root.contains(document.activeElement) ? document.activeElement?.dataset?.addSection : null;
  const selection = focusedSection ? document.activeElement.selectionStart : null;
  root.setAttribute('aria-busy', 'true');
  try {
    if (activeId) {
      try { current = await db.loadList(activeId); }
      catch (err) { if (err.message !== 'List not found on this device') throw err; activeId = null; sessionStorage.removeItem('shared-list-active'); current = null; }
    }
    const view = activeId ? showList(current) : showLists(await db.listDocuments());
    if (version !== renderVersion) return;
    root.replaceChildren(view);
    root.setAttribute('aria-busy', 'false');
    if (focusedSection) {
      const input = root.querySelector(`[data-add-section="${focusedSection}"]`);
      if (input) { input.focus({ preventScroll: true }); input.setSelectionRange(selection, selection); }
    }
    window.scrollTo(0, previousY);
  } catch (err) {
    root.setAttribute('aria-busy', 'false');
    fail(err);
    if (!root.childElementCount) root.append(node('main', { class: 'shell' }, node('h1', { text: t('storageError') })));
  }
}
db.subscribe(() => render());
document.addEventListener('visibilitychange', () => { if (!document.hidden) render(); });
render();
if ('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(console.warn);
