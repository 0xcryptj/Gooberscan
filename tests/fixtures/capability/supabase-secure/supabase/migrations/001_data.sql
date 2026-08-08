create table public.api_tokens (
  id uuid primary key,
  owner_id uuid not null,
  token text not null,
  tenant_id uuid not null
);

alter table public.api_tokens enable row level security;
alter table public.api_tokens force row level security;

create policy "owners read their tokens"
on public.api_tokens for select to authenticated
using (auth.uid() = owner_id);

create policy "owners update their tokens"
on public.api_tokens for update to authenticated
using (auth.uid() = owner_id)
with check (auth.uid() = owner_id);

revoke all on public.api_tokens from anon;
revoke execute on function public.export_tokens() from anon;
