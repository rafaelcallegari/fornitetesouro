-- =====================================================================
-- Rastreador de Baús - Treasure Hunt (Fortnite) - versão ANÔNIMA
-- Instalação do zero: Supabase > SQL Editor > New query > Run
-- Depois rode o bloco "SENHA DO ADMIN" no fim, trocando a senha.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- Tabelas ----------
create table if not exists public.chests (
  id         bigint generated always as identity primary key,
  device_id  uuid not null,                       -- id aleatório do navegador (fica oculto)
  nick       text check (char_length(nick) <= 24), -- apelido opcional
  opened_at  timestamptz not null default now(),
  poi        text not null check (char_length(poi) between 1 and 40),
  chest_type text not null default 'normal'
             check (chest_type in ('normal','raro','enterrado','sprite','cofre')),
  prize      text not null check (char_length(prize) between 1 and 40),
  tier       text not null
             check (tier in ('nada','gizmo','cosmetico','veiculo','dourado','token')),
  x          real check (x between 0 and 1),
  y          real check (y between 0 and 1),
  created_at timestamptz not null default now()
);
create index if not exists chests_opened_at_idx on public.chests (opened_at);
create index if not exists chests_device_idx on public.chests (device_id, created_at desc);

create table if not exists public.event_windows (
  id        bigint generated always as identity primary key,
  label     text not null default 'Treasure Hour' check (char_length(label) <= 60),
  starts_at timestamptz not null,
  ends_at   timestamptz not null,
  check (ends_at > starts_at)
);

-- Configuração privada (fora da API pública)
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
create table if not exists private.settings (key text primary key, value text not null);

-- ---------- Proteção básica de cada registro ----------
create or replace function public.chests_guard()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from public.chests
      where device_id = new.device_id and created_at > now() - interval '1 minute') >= 20 then
    raise exception 'Muitos registros em 1 minuto, espere um pouco';
  end if;
  if new.opened_at > now() + interval '5 minutes'
     or new.opened_at < now() - interval '3 days' then
    raise exception 'Horário do baú fora do permitido (até 3 dias atrás)';
  end if;
  new.created_at := now();
  return new;
end $$;
drop trigger if exists chests_guard on public.chests;
create trigger chests_guard before insert on public.chests
  for each row execute function public.chests_guard();

-- ---------- Acesso público ----------
alter table public.chests        enable row level security;
alter table public.event_windows enable row level security;

drop policy if exists "chests leitura" on public.chests;
drop policy if exists "chests grava"   on public.chests;
create policy "chests leitura" on public.chests for select to anon, authenticated using (true);
create policy "chests grava"   on public.chests for insert to anon, authenticated with check (true);

drop policy if exists "janelas leitura" on public.event_windows;
create policy "janelas leitura" on public.event_windows for select to anon, authenticated using (true);

-- device_id não pode ser lido por ninguém (senão qualquer um apagaria o registro dos outros)
revoke all on public.chests from anon, authenticated;
grant select (id, nick, opened_at, poi, chest_type, prize, tier, x, y) on public.chests to anon, authenticated;
grant insert (device_id, nick, opened_at, poi, chest_type, prize, tier, x, y) on public.chests to anon, authenticated;
revoke all on public.event_windows from anon, authenticated;
grant select on public.event_windows to anon, authenticated;

-- ---------- Estatística ----------
create or replace view public.chest_hourly with (security_invoker = true) as
select date_trunc('hour', c.opened_at) as hour_utc,
       exists (select 1 from public.event_windows w
               where c.opened_at >= w.starts_at and c.opened_at < w.ends_at) as in_window,
       c.poi, c.tier, count(*)::int as n
from public.chests c
group by 1, 2, 3, 4;
grant select on public.chest_hourly to anon, authenticated;

create or replace function public.chest_totals()
returns table (chests int, players int) language sql stable security definer set search_path = public as $$
  select count(*)::int, count(distinct device_id)::int from public.chests;
$$;

-- ---------- Registros do próprio aparelho ----------
create or replace function public.my_chests(p_device uuid)
returns table (id bigint, opened_at timestamptz, poi text, prize text, tier text)
language sql stable security definer set search_path = public as $$
  select c.id, c.opened_at, c.poi, c.prize, c.tier from public.chests c
  where c.device_id = p_device order by c.id desc limit 15;
$$;

create or replace function public.delete_my_chest(p_id bigint, p_device uuid)
returns void language sql security definer set search_path = public as $$
  delete from public.chests where id = p_id and device_id = p_device;
$$;

-- ---------- Admin (senha) ----------
create or replace function private.admin_ok(p_key text)
returns boolean language sql stable security definer set search_path = private, extensions as $$
  select exists (select 1 from private.settings
                 where key = 'admin_hash' and value = extensions.crypt(p_key, value));
$$;

create or replace function public.admin_check(p_key text)
returns boolean language sql stable security definer set search_path = public as $$
  select private.admin_ok(p_key);
$$;

create or replace function public.admin_add_window(p_key text, p_label text, p_start timestamptz, p_end timestamptz)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not private.admin_ok(p_key) then raise exception 'Senha de admin incorreta'; end if;
  insert into public.event_windows (label, starts_at, ends_at)
  values (coalesce(nullif(p_label, ''), 'Treasure Hour'), p_start, p_end);
end $$;

create or replace function public.admin_delete_window(p_key text, p_id bigint)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not private.admin_ok(p_key) then raise exception 'Senha de admin incorreta'; end if;
  delete from public.event_windows where id = p_id;
end $$;

create or replace function public.admin_recent(p_key text)
returns table (id bigint, opened_at timestamptz, poi text, prize text, nick text, device text)
language plpgsql stable security definer set search_path = public as $$
begin
  if not private.admin_ok(p_key) then raise exception 'Senha de admin incorreta'; end if;
  return query select c.id, c.opened_at, c.poi, c.prize, c.nick, left(c.device_id::text, 8)
               from public.chests c order by c.id desc limit 50;
end $$;

create or replace function public.admin_delete_chest(p_key text, p_id bigint)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not private.admin_ok(p_key) then raise exception 'Senha de admin incorreta'; end if;
  delete from public.chests where id = p_id;
end $$;

-- apaga tudo do mesmo aparelho do registro informado (para spam)
create or replace function public.admin_delete_device(p_key text, p_id bigint)
returns int language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not private.admin_ok(p_key) then raise exception 'Senha de admin incorreta'; end if;
  delete from public.chests where device_id = (select device_id from public.chests where id = p_id);
  get diagnostics n = row_count;
  return n;
end $$;

-- ---------- Permissões das funções ----------
revoke execute on function public.chests_guard() from public, anon, authenticated;
revoke execute on function private.admin_ok(text) from public, anon, authenticated;
revoke execute on function public.chest_totals(), public.my_chests(uuid), public.delete_my_chest(bigint, uuid),
  public.admin_check(text), public.admin_add_window(text, text, timestamptz, timestamptz),
  public.admin_delete_window(text, bigint), public.admin_recent(text),
  public.admin_delete_chest(text, bigint), public.admin_delete_device(text, bigint) from public;
grant execute on function public.chest_totals(), public.my_chests(uuid), public.delete_my_chest(bigint, uuid),
  public.admin_check(text), public.admin_add_window(text, text, timestamptz, timestamptz),
  public.admin_delete_window(text, bigint), public.admin_recent(text),
  public.admin_delete_chest(text, bigint), public.admin_delete_device(text, bigint) to anon, authenticated;

-- ---------- Janelas já anunciadas (Treasure Hour de 07/11/2026) ----------
insert into public.event_windows (label, starts_at, ends_at)
select * from (values
  ('Treasure Hour 1 (07/11)', timestamptz '2026-11-07 19:00:00+00', timestamptz '2026-11-07 21:00:00+00'),
  ('Treasure Hour 2 (07/11)', timestamptz '2026-11-08 02:00:00+00', timestamptz '2026-11-08 04:00:00+00')
) v(label, starts_at, ends_at)
where not exists (select 1 from public.event_windows);

-- ---------- SENHA DO ADMIN (troque e rode) ----------
-- insert into private.settings (key, value)
-- values ('admin_hash', extensions.crypt('TROQUE_ESTA_SENHA', extensions.gen_salt('bf')))
-- on conflict (key) do update set value = excluded.value;
