create table public.api_tokens (
  id uuid primary key,
  owner_id uuid not null,
  token text not null,
  tenant_id uuid not null
);

create table public.private_messages (
  id uuid primary key,
  sender_id uuid not null,
  recipient_id uuid not null,
  body text not null
);

grant select, insert, update on public.api_tokens to anon, authenticated;

create or replace function public.export_tokens()
returns setof public.api_tokens
language sql
security definer
as $$ select * from public.api_tokens $$;

grant execute on function public.export_tokens() to anon;
