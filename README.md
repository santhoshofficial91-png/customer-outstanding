# Customer Outstanding Tracker

Single-page web app (`index.html`) on Supabase (Auth, Postgres with row-level security, Realtime, Storage, one Edge Function).

- Live site: GitHub Pages (`main` branch, root folder)
- Database schema: `supabase/schema.sql`
- User management function: `supabase/functions/manage-users/index.ts`

Roles: Admin, Sub Admin, Manager, Executive. Users sign in with a username and password. Admin and Sub Admin create users from the app.
