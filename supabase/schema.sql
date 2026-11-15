
create table public.docs(col text not null, id text not null, data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now(), primary key(col,id));
create index docs_col_idx on public.docs(col);
alter table public.docs enable row level security;
create table public.user_secrets(user_id text primary key, pw text not null);
alter table public.user_secrets enable row level security;

create function public.my_role() returns text language sql stable security definer set search_path = public as $$
  select case when (data->>'active') is distinct from 'false' then data->>'role' end from public.docs where col='users' and id = (select auth.uid())::text
$$;
revoke all on function public.my_role() from public, anon;
grant execute on function public.my_role() to authenticated;

create policy docs_select on public.docs for select to authenticated using (public.my_role() is not null);
create policy docs_insert on public.docs for insert to authenticated with check ((col <> 'users' and public.my_role() is not null) or (col = 'users' and public.my_role() = 'Admin'));
create policy docs_update on public.docs for update to authenticated
  using ((col <> 'users' and public.my_role() is not null) or (col = 'users' and (public.my_role() = 'Admin' or id = (select auth.uid())::text)))
  with check ((col <> 'users' and public.my_role() is not null) or (col = 'users' and (public.my_role() = 'Admin' or id = (select auth.uid())::text)));
create policy docs_delete on public.docs for delete to authenticated using ((col <> 'users' and public.my_role() is not null) or (col = 'users' and public.my_role() = 'Admin'));

create function public.docs_guard() returns trigger language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  if tg_op = 'UPDATE' and new.col = 'users' and (select auth.uid()) is not null and public.my_role() is distinct from 'Admin' then
    if (new.data->>'role') is distinct from (old.data->>'role') or (new.data->'subs') is distinct from (old.data->'subs')
       or (new.data->>'active') is distinct from (old.data->>'active') or (new.data->>'managerId') is distinct from (old.data->>'managerId')
       or (new.data->>'username') is distinct from (old.data->>'username') then
      raise exception 'Not allowed to change role, areas, status or username';
    end if;
  end if;
  return new;
end $$;
revoke all on function public.docs_guard() from public, anon, authenticated;
create trigger docs_guard_trg before insert or update on public.docs for each row execute function public.docs_guard();

create policy secrets_admin on public.user_secrets for all to authenticated using (public.my_role() = 'Admin') with check (public.my_role() = 'Admin');

alter publication supabase_realtime add table public.docs;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values ('chat-images','chat-images',true,2097152,array['image/jpeg','image/png','image/webp']);
create policy chat_img_insert on storage.objects for insert to authenticated with check (bucket_id = 'chat-images' and public.my_role() is not null);
