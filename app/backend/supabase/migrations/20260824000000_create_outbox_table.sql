-- Transactional Outbox for Domain Events (issue #807)
-- Events are recorded durably in the same transaction as the originating
-- state change and later dispatched at-least-once by the outbox dispatcher.

create table if not exists public.outbox (
  id              uuid        primary key,
  event_id        text        not null,
  aggregate_type  text        not null,
  aggregate_id    text        not null,
  event_type      text        not null,
  payload         jsonb       not null default '{}'::jsonb,
  status          text        not null default 'pending'
                    check (status in ('pending', 'dispatched', 'failed')),
  attempts        integer     not null default 0,
  next_attempt_at timestamptz not null default now(),
  last_error      text,
  created_at      timestamptz not null default now(),
  dispatched_at   timestamptz
);

create index if not exists outbox_dispatch_idx
  on public.outbox (status, next_attempt_at);

create index if not exists outbox_event_id_idx
  on public.outbox (event_id);

comment on table public.outbox is
  'Transactional outbox. Rows are written atomically with domain state changes '
  'and dispatched at-least-once by the outbox dispatcher.';

-- Reference implementation of the same-transaction pattern: the username
-- insert and the outbox insert happen inside one atomic function call, so a
-- crash between commit and dispatch cannot lose the event.
create or replace function public.claim_username_with_outbox(
  p_username  text,
  p_public_key text,
  p_event_id text,
  p_payload  jsonb
) returns void
language plpgsql
as $$
begin
  insert into public.usernames (username, public_key)
  values (p_username, p_public_key);

  insert into public.outbox (
    id, event_id, aggregate_type, aggregate_id,
    event_type, payload, status, next_attempt_at
  ) values (
    gen_random_uuid(), p_event_id, 'username', p_username,
    'username.claimed', p_payload, 'pending', now()
  );
end;
$$;

do $$
declare
  role_name text;
begin
  foreach role_name in array array['authenticated', 'service_role'] loop
    if exists (select 1 from pg_roles where rolname = role_name) then
      execute format(
        'grant execute on function public.claim_username_with_outbox(text, text, text, jsonb) to %I',
        role_name
      );
    end if;
  end loop;
end
$$;
