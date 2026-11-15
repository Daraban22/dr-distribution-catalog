-- Row Level Security checks. Everything runs inside one DO block that ends by
-- raising an exception, so the temporary test users, staff row and items are all
-- rolled back. Nothing is left in the database.
do $$
declare
  staff_id uuid := gen_random_uuid();
  other_id uuid := gen_random_uuid();
  out text := '';
  n integer;
  ok boolean;
  item bigint;
  procedure_note text;
begin
  insert into auth.users (id, instance_id, aud, role, email, encrypted_password, created_at, updated_at)
  values (staff_id, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'rls-test-staff@example.invalid', '', now(), now()),
         (other_id, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'rls-test-other@example.invalid', '', now(), now());
  insert into public.staff (user_id, display_name) values (staff_id, 'RLS test');
  insert into public.inventory_items (name, quantity, unit) values ('Pre-existing test tray', 5, 'case');

  -- 1. anonymous visitor
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  execute 'set local role anon';
  begin perform count(*) from public.inventory_items; out := out || 'FAIL anon-read-items;'; exception when insufficient_privilege then out := out || 'PASS anon-read-items;'; end;
  begin perform count(*) from public.inventory_audit; out := out || 'FAIL anon-read-audit;'; exception when insufficient_privilege then out := out || 'PASS anon-read-audit;'; end;
  begin perform count(*) from public.staff; out := out || 'FAIL anon-read-staff;'; exception when insufficient_privilege then out := out || 'PASS anon-read-staff;'; end;
  begin insert into public.inventory_items (name, quantity, unit) values ('x', 1, 'case'); out := out || 'FAIL anon-insert;'; exception when insufficient_privilege then out := out || 'PASS anon-insert;'; end;
  begin perform public.restore_inventory('[{"name":"x","quantity":1,"unit":"case"}]'); out := out || 'FAIL anon-restore;'; exception when insufficient_privilege then out := out || 'PASS anon-restore;'; end;
  execute 'reset role';

  -- 2. signed in but not staff
  perform set_config('request.jwt.claims', json_build_object('sub', other_id, 'role', 'authenticated')::text, true);
  execute 'set local role authenticated';
  select count(*) into n from public.inventory_items;
  out := out || case when n = 0 then 'PASS nonstaff-sees-nothing;' else 'FAIL nonstaff-sees-nothing;' end;
  select count(*) into n from public.inventory_audit;
  out := out || case when n = 0 then 'PASS nonstaff-no-history;' else 'FAIL nonstaff-no-history;' end;
  select count(*) into n from public.staff;
  out := out || case when n = 0 then 'PASS nonstaff-no-staff-list;' else 'FAIL nonstaff-no-staff-list;' end;
  begin insert into public.inventory_items (name, quantity, unit) values ('x', 1, 'case'); out := out || 'FAIL nonstaff-insert;'; exception when insufficient_privilege then out := out || 'PASS nonstaff-insert;'; end;
  update public.inventory_items set quantity = 99; get diagnostics n = row_count;
  out := out || case when n = 0 then 'PASS nonstaff-update;' else 'FAIL nonstaff-update;' end;
  delete from public.inventory_items; get diagnostics n = row_count;
  out := out || case when n = 0 then 'PASS nonstaff-delete;' else 'FAIL nonstaff-delete;' end;
  begin perform public.restore_inventory('[{"name":"x","quantity":1,"unit":"case"}]'); out := out || 'FAIL nonstaff-restore;'; exception when insufficient_privilege then out := out || 'PASS nonstaff-restore;'; end;
  begin insert into public.staff (user_id) values (other_id); out := out || 'FAIL nonstaff-self-enrol;'; exception when insufficient_privilege then out := out || 'PASS nonstaff-self-enrol;'; end;
  execute 'reset role';

  -- 3. staff member
  perform set_config('request.jwt.claims', json_build_object('sub', staff_id, 'role', 'authenticated')::text, true);
  execute 'set local role authenticated';
  select count(*) into n from public.inventory_items;
  out := out || case when n = 1 then 'PASS staff-read;' else 'FAIL staff-read;' end;
  insert into public.inventory_items (name, sku, quantity, unit, notes) values ('Disposable review tray', '', 3, 'case', '') returning id into item;
  update public.inventory_items set quantity = 4 where id = item;
  select quantity = 4 into ok from public.inventory_items where id = item;
  out := out || case when ok then 'PASS staff-create-update;' else 'FAIL staff-create-update;' end;
  select count(*) into n from public.inventory_audit where item_id = item and actor = staff_id;
  out := out || case when n = 2 then 'PASS audit-records-actor;' else 'FAIL audit-records-actor(' || n || ');' end;
  begin insert into public.inventory_audit (action) values ('forged'); out := out || 'FAIL staff-forge-audit;'; exception when insufficient_privilege then out := out || 'PASS staff-forge-audit;'; end;
  begin update public.inventory_items set updated_by = other_id where id = item; out := out || 'FAIL staff-spoof-updated-by;'; exception when insufficient_privilege then out := out || 'PASS staff-spoof-updated-by;'; end;
  begin insert into public.staff (user_id) values (other_id); out := out || 'FAIL staff-add-staff;'; exception when insufficient_privilege then out := out || 'PASS staff-add-staff;'; end;
  begin insert into public.inventory_items (name, quantity, unit) values ('x', -1, 'case'); out := out || 'FAIL qty-negative;'; exception when check_violation then out := out || 'PASS qty-negative;'; end;
  begin insert into public.inventory_items (name, quantity, unit) values ('x', 1000001, 'case'); out := out || 'FAIL qty-too-big;'; exception when check_violation then out := out || 'PASS qty-too-big;'; end;
  begin insert into public.inventory_items (name, quantity, unit) values (repeat('a', 201), 1, 'case'); out := out || 'FAIL name-too-long;'; exception when check_violation then out := out || 'PASS name-too-long;'; end;
  begin insert into public.inventory_items (name, quantity, unit) values ('bad' || chr(10) || 'name', 1, 'case'); out := out || 'FAIL name-control-char;'; exception when check_violation then out := out || 'PASS name-control-char;'; end;
  begin perform public.restore_inventory('[]'); out := out || 'FAIL restore-empty;'; exception when invalid_parameter_value then out := out || 'PASS restore-empty;'; end;
  begin perform public.restore_inventory('[{"name":"x","quantity":"1e2","unit":"case"}]'); out := out || 'FAIL restore-1e2;'; exception when invalid_parameter_value then out := out || 'PASS restore-1e2;'; end;
  begin perform public.restore_inventory('{"items":1}'); out := out || 'FAIL restore-not-list;'; exception when invalid_parameter_value then out := out || 'PASS restore-not-list;'; end;
  begin perform public.restore_inventory('[{"name":"ok","quantity":1,"unit":"case"},{"name":"","quantity":1,"unit":"case"}]'); out := out || 'FAIL restore-bad-record;'; exception when check_violation or invalid_parameter_value then out := out || 'PASS restore-bad-record;'; end;
  select count(*) into n from public.inventory_items;
  out := out || case when n = 2 then 'PASS failed-restore-keeps-records;' else 'FAIL failed-restore-keeps-records(' || n || ');' end;
  perform public.restore_inventory('[{"name":"Restored tray","quantity":7,"unit":"case"}]');
  select count(*) into n from public.inventory_items;
  out := out || case when n = 1 then 'PASS restore-replaces;' else 'FAIL restore-replaces;' end;
  select count(*) into n from public.staff;
  out := out || case when n = 1 then 'PASS restore-keeps-account;' else 'FAIL restore-keeps-account;' end;
  delete from public.inventory_items; get diagnostics n = row_count;
  out := out || case when n = 1 then 'PASS staff-delete;' else 'FAIL staff-delete;' end;
  execute 'reset role';

  raise exception 'RLS_RESULTS %', out;
end;
$$;
