// Same limits as the Nov 8 server package, enforced again by database checks.
export const LIMITS = { name: 200, sku: 64, unit: 40, notes: 2000, quantity: 1000000, restore: 2000 };
export const SESSION_MS = 12 * 60 * 60 * 1000;
export const LOGIN_LIMIT = 8;
export const LOGIN_WINDOW_MS = 15 * 60 * 1000;

const CONTROL = /[\u0000-\u001F]/;
const CONTROL_NOTES = /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/;

function clean(value, max, label, { required = false, notes = false } = {}) {
  const text = String(value ?? "").trim();
  if ((notes ? CONTROL_NOTES : CONTROL).test(text)) return { error: `${label} contains characters that are not allowed.` };
  if (text.length > max) return { error: `${label} is too long.` };
  if (required && !text) return { error: `${label} is required.` };
  return { text };
}

export function wholeQuantity(value) {
  if (typeof value === "number") {
    return Number.isInteger(value) && value >= 0 && value <= LIMITS.quantity ? value : null;
  }
  const text = String(value ?? "").trim();
  if (!/^(0|[1-9]\d*)$/.test(text)) return null;
  const n = Number(text);
  return n <= LIMITS.quantity ? n : null;
}

export function validateItem(input) {
  const errors = [];
  const value = {};
  const fields = [
    ["name", LIMITS.name, "Item name", { required: true }],
    ["sku", LIMITS.sku, "SKU", {}],
    ["unit", LIMITS.unit, "Unit", { required: true }],
    ["notes", LIMITS.notes, "Notes", { notes: true }],
  ];
  for (const [key, max, label, opts] of fields) {
    const r = clean(input?.[key], max, label, opts);
    if (r.error) errors.push(r.error);
    else value[key] = r.text;
  }
  const quantity = wholeQuantity(input?.quantity);
  if (quantity === null) errors.push("Quantity must be a whole number from 0 through 1000000.");
  else value.quantity = quantity;
  return errors.length ? { ok: false, errors } : { ok: true, value };
}

export function validateBackup(parsed) {
  const items = parsed && Array.isArray(parsed.items) ? parsed.items : null;
  if (!items) return { ok: false, errors: ["The backup must contain an item list."] };
  if (items.length === 0) return { ok: false, errors: ["A backup has to include the records to keep. An empty file is refused so it cannot erase the inventory."] };
  if (items.length > LIMITS.restore) return { ok: false, errors: ["A backup can contain at most 2000 records."] };
  const out = [];
  const errors = [];
  items.forEach((item, i) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) { errors.push(`Record ${i + 1} is not valid.`); return; }
    const r = validateItem(item);
    if (!r.ok) errors.push(`Record ${i + 1}: ${r.errors.join(" ")}`);
    else out.push(r.value);
  });
  return errors.length ? { ok: false, errors: errors.slice(0, 20) } : { ok: true, items: out };
}

// Client-side reminder of the server-side Supabase Auth rate limit. It only
// slows a person using this page; the real limit is enforced by Supabase Auth.
export function loginThrottle(store, now = Date.now()) {
  const raw = (() => { try { return JSON.parse(store.getItem("dr_login_failures") || "[]"); } catch { return []; } })();
  const recent = raw.filter((t) => typeof t === "number" && now - t < LOGIN_WINDOW_MS);
  return {
    locked: recent.length >= LOGIN_LIMIT,
    fail() { recent.push(now); store.setItem("dr_login_failures", JSON.stringify(recent)); },
    clear() { store.removeItem("dr_login_failures"); },
  };
}

export function sessionExpired(startedAt, now = Date.now()) {
  const t = Number(startedAt);
  return !Number.isFinite(t) || now - t > SESSION_MS || t > now + 60000;
}
