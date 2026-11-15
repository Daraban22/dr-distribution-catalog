-- DR Distribution inventory on Supabase.
-- Access model: a person must (1) sign in with Supabase Auth and (2) be listed in
-- public.staff. Being signed in alone grants nothing, so a stray sign-up cannot
-- read or change inventory. Nobody can add themselves to staff from the browser;
-- the owner adds staff with SQL in the Supabase dashboard.

create table public.staff (
  user_id uuid primary key references auth.users (id) on delete cascade,
  display_name text not null default '' check (char_length(display_name) <= 80),
  created_at timestamptz not null default now()
);

create table public.inventory_items (
  id bigint generated always as identity primary key,
  name text not null check (char_length(name) between 1 and 200 and name !~ '[\x01-\x1f]'),
  sku text not null default '' check (char_length(sku) <= 64 and sku !~ '[\x01-\x1f]'),
  quantity integer not null check (quantity between 0 and 1000000),
  unit text not null check (char_length(unit) between 1 and 40 and unit !~ '[\x01-\x1f]'),
  notes text not null default '' check (char_length(notes) <= 2000 and notes !~ '[\x01-\x08\x0b\x0c\x0e-\x1f]'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid()
);

create table public.inventory_audit (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  actor uuid,
  actor_email text,
  action text not null,
  item_id bigint,
  before_json jsonb,
  after_json jsonb
);

-- Helper used by every policy. security definer so it can read staff without
-- exposing the staff list. Kept in a private schema so it is not an API endpoint.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.is_staff()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.staff s where s.user_id = (select auth.uid()));
$$;

revoke all on function private.is_staff() from public, anon;
grant execute on function private.is_staff() to authenticated;

-- Audit trigger: every insert, update and delete is recorded server-side.
create or replace function public.inventory_audit_trigger()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if current_setting('dr.bulk_restore', true) = 'on' then
    return coalesce(new, old);
  end if;
  if tg_op = 'UPDATE' then
    new.updated_at := now();
    new.updated_by := auth.uid();
  end if;
  insert into public.inventory_audit (actor, actor_email, action, item_id, before_json, after_json)
  values (
    auth.uid(),
    (select u.email from auth.users u where u.id = auth.uid()),
    lower(tg_op),
    coalesce(new.id, old.id),
    case when tg_op in ('UPDATE','DELETE') then to_jsonb(old) end,
    case when tg_op in ('INSERT','UPDATE') then to_jsonb(new) end
  );
  return coalesce(new, old);
end;
$$;

revoke all on function public.inventory_audit_trigger() from public, anon, authenticated;

create trigger inventory_items_audit_ins after insert or delete on public.inventory_items
  for each row execute function public.inventory_audit_trigger();
create trigger inventory_items_audit_upd before update on public.inventory_items
  for each row execute function public.inventory_audit_trigger();

-- Row Level Security
alter table public.staff enable row level security;
alter table public.inventory_items enable row level security;
alter table public.inventory_audit enable row level security;

revoke all on public.staff, public.inventory_items, public.inventory_audit from anon, public;
revoke all on public.staff, public.inventory_items, public.inventory_audit from authenticated;
grant select on public.staff to authenticated;
grant select, insert, update, delete on public.inventory_items to authenticated;
grant select on public.inventory_audit to authenticated;
revoke insert, update on public.inventory_items from authenticated;
grant insert (name, sku, quantity, unit, notes) on public.inventory_items to authenticated;
grant update (name, sku, quantity, unit, notes) on public.inventory_items to authenticated;

create policy "staff see own row" on public.staff
  for select to authenticated using (user_id = (select auth.uid()));

create policy "staff read inventory" on public.inventory_items
  for select to authenticated using ((select private.is_staff()));
create policy "staff add inventory" on public.inventory_items
  for insert to authenticated with check ((select private.is_staff()));
create policy "staff change inventory" on public.inventory_items
  for update to authenticated using ((select private.is_staff())) with check ((select private.is_staff()));
create policy "staff remove inventory" on public.inventory_items
  for delete to authenticated using ((select private.is_staff()));

create policy "staff read history" on public.inventory_audit
  for select to authenticated using ((select private.is_staff()));

-- Restore: replaces the item list only with a valid, non-empty list of at most
-- 2000 records, in one transaction. Accounts are never touched.
create or replace function public.restore_inventory(items jsonb)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  n integer;
  rec jsonb;
begin
  if not private.is_staff() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  if items is null or jsonb_typeof(items) <> 'array' then
    raise exception 'The backup must contain an item list.' using errcode = '22023';
  end if;
  n := jsonb_array_length(items);
  if n = 0 then
    raise exception 'A backup has to include the records to keep. An empty file is refused so it cannot erase the inventory.' using errcode = '22023';
  end if;
  if n > 2000 then
    raise exception 'A backup can contain at most 2000 records.' using errcode = '22023';
  end if;
  for rec in select * from jsonb_array_elements(items) loop
    if jsonb_typeof(rec) <> 'object'
       or jsonb_typeof(rec->'quantity') <> 'number'
       or jsonb_typeof(rec->'name') <> 'string'
       or jsonb_typeof(rec->'unit') <> 'string' then
      raise exception 'A record in the backup is not valid.' using errcode = '22023';
    end if;
    if (rec->>'quantity') !~ '^(0|[1-9][0-9]*)$' then
      raise exception 'Quantity must be a whole number from 0 through 1000000.' using errcode = '22023';
    end if;
  end loop;

  perform set_config('dr.bulk_restore', 'on', true);
  delete from public.inventory_items where true;
  insert into public.inventory_items (name, sku, quantity, unit, notes)
  select btrim(r->>'name'), btrim(coalesce(r->>'sku', '')), (r->>'quantity')::integer,
         btrim(r->>'unit'), btrim(coalesce(r->>'notes', ''))
  from jsonb_array_elements(items) r;
  perform set_config('dr.bulk_restore', 'off', true);

  insert into public.inventory_audit (actor, actor_email, action, after_json)
  values (auth.uid(), (select u.email from auth.users u where u.id = auth.uid()), 'restore', jsonb_build_object('count', n));
  return n;
end;
$$;

revoke all on function public.restore_inventory(jsonb) from public, anon;
grant execute on function public.restore_inventory(jsonb) to authenticated;
