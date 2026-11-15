import { supabase, currentStaff } from "./client.js";
import { validateItem, validateBackup } from "./validate.js";

const $ = (s) => document.querySelector(s);
const state = { items: [] };

const user = await currentStaff();
if (!user) {
  location.replace("login/");
} else {
  $("#gate").hidden = true;
  $("#app").hidden = false;
  $("#who").textContent = `Signed in as ${user.email}`;
  await load();
}

function cell(row, value) {
  const td = document.createElement("td");
  td.textContent = value == null ? "" : String(value);
  row.append(td);
  return td;
}

function table(headers) {
  const t = document.createElement("table");
  const head = t.createTHead().insertRow();
  for (const h of headers) { const th = document.createElement("th"); th.textContent = h; head.append(th); }
  return [t, t.createTBody()];
}

function render() {
  const q = $("#search").value.trim().toLowerCase();
  const rows = state.items.filter((i) => !q || [i.name, i.sku, i.unit, i.notes].join(" ").toLowerCase().includes(q));
  const list = $("#list");
  list.replaceChildren();
  if (!rows.length) { const p = document.createElement("p"); p.textContent = "No inventory records yet."; list.append(p); return; }
  const [t, body] = table(["Item", "SKU", "Quantity", "Unit", "Notes", ""]);
  for (const item of rows) {
    const tr = body.insertRow();
    cell(tr, item.name); cell(tr, item.sku); cell(tr, item.quantity); cell(tr, item.unit); cell(tr, item.notes);
    const b = document.createElement("button");
    b.type = "button"; b.textContent = "Edit";
    b.addEventListener("click", () => edit(item));
    cell(tr, "").append(b);
  }
  list.append(t);
}

async function guarded(promise) {
  const result = await promise;
  if (result.error && (result.error.code === "42501" || result.status === 401)) { location.replace("login/"); }
  return result;
}

async function load() {
  const { data, error } = await guarded(supabase.from("inventory_items").select("id,name,sku,quantity,unit,notes,updated_at").order("name"));
  if (error) { $("#form-error").textContent = "The inventory could not be loaded."; return; }
  state.items = data;
  render();
  const audit = await guarded(supabase.from("inventory_audit").select("created_at,actor_email,action,item_id").order("created_at", { ascending: false }).limit(200));
  const box = $("#audit");
  box.replaceChildren();
  if (audit.error || !audit.data.length) { const p = document.createElement("p"); p.textContent = audit.error ? "History could not be loaded." : "No changes yet."; box.append(p); return; }
  const [t, body] = table(["When", "Who", "Action", "Item"]);
  for (const e of audit.data) { const tr = body.insertRow(); cell(tr, new Date(e.created_at).toLocaleString()); cell(tr, e.actor_email); cell(tr, e.action); cell(tr, e.item_id); }
  box.append(t);
}

function edit(item) {
  for (const k of ["name", "sku", "quantity", "unit", "notes"]) $("#" + k).value = item[k] ?? "";
  $("#item-id").value = String(item.id);
  $("#delete").hidden = false;
}

function clearForm() {
  for (const k of ["item-id", "name", "sku", "quantity", "unit", "notes"]) $("#" + k).value = "";
  $("#form-error").textContent = "";
  $("#delete").hidden = true;
}

$("#search").addEventListener("input", render);
$("#reset").addEventListener("click", clearForm);

$("#editor").addEventListener("submit", async (event) => {
  event.preventDefault();
  const r = validateItem({ name: $("#name").value, sku: $("#sku").value, quantity: $("#quantity").value, unit: $("#unit").value, notes: $("#notes").value });
  if (!r.ok) { $("#form-error").textContent = r.errors.join(" "); return; }
  const id = Number($("#item-id").value);
  const q = id ? supabase.from("inventory_items").update(r.value).eq("id", id) : supabase.from("inventory_items").insert(r.value);
  const { error } = await guarded(q);
  if (error) { $("#form-error").textContent = "The record was not saved."; return; }
  clearForm();
  await load();
});

$("#delete").addEventListener("click", async () => {
  const id = Number($("#item-id").value);
  if (!id || !confirm("Delete this record?")) return;
  const { error } = await guarded(supabase.from("inventory_items").delete().eq("id", id));
  if (error) { $("#form-error").textContent = "The record was not deleted."; return; }
  clearForm();
  await load();
});

$("#export").addEventListener("click", async () => {
  const items = await guarded(supabase.from("inventory_items").select("name,sku,quantity,unit,notes,created_at,updated_at").order("id"));
  const audit = await guarded(supabase.from("inventory_audit").select("created_at,actor_email,action,item_id,before_json,after_json").order("id"));
  if (items.error || audit.error) { $("#form-error").textContent = "The backup could not be made."; return; }
  const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), items: items.data, audit: audit.data }, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `dr-inventory-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

$("#restore").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("#restore-error");
  out.textContent = "";
  const file = $("#restore-file").files[0];
  if (!file) { out.textContent = "Choose a backup file first."; return; }
  if (file.size > 2_000_000) { out.textContent = "That file is too large."; return; }
  let parsed;
  try { parsed = JSON.parse(await file.text()); } catch { out.textContent = "That file could not be read as a backup."; return; }
  const r = validateBackup(parsed);
  if (!r.ok) { out.textContent = r.errors.join(" "); return; }
  if (!confirm(`Replace every current record with the ${r.items.length} records in this file?`)) return;
  const { error } = await guarded(supabase.rpc("restore_inventory", { items: r.items }));
  if (error) { out.textContent = "The restore was refused. The current records were kept."; return; }
  await load();
});

$("#logout").addEventListener("click", async () => {
  await supabase.auth.signOut({ scope: "local" });
  sessionStorage.removeItem("dr_signed_in_at");
  location.replace("login/");
});
