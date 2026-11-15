# Inventory entry preview (not live)

This branch is a staging copy. GitHub Pages serves only `main`, so nothing on this branch is on the public site.

- `inventory/` – static sign-in and inventory pages. They talk to the DR Distribution Supabase project from the browser with the publishable key. Row Level Security in the database decides access: a person must be signed in **and** listed in `public.staff`.
- `supabase/migrations/` – the database tables, security rules and restore function.
- `supabase/tests/rls_test.sql` – database security checks. It runs inside one block that rolls back, so it leaves no data.

No accounts exist yet and no inventory data was imported. The service-role key is not in this repository.
