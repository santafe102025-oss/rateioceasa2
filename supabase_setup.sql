-- Execute UMA VEZ no SQL Editor do Supabase.

create extension if not exists "uuid-ossp";

create table if not exists public.empresas (
  id uuid primary key default uuid_generate_v4(),
  cnpj text unique not null,
  nome text not null,
  box  text not null,
  email text unique not null,
  created_at timestamp default now()
);

alter table public.empresas enable row level security;

-- Policies: usuários autenticados podem inserir/ler
drop policy if exists "empresas_insert_auth" on public.empresas;
drop policy if exists "empresas_select_auth" on public.empresas;

create policy "empresas_insert_auth"
  on public.empresas for insert
  to authenticated
  with check (true);

create policy "empresas_select_auth"
  on public.empresas for select
  to authenticated
  using (true);

-- STORAGE:
-- Crie um bucket privado chamado 'rateios' no Storage.
-- Sugestões de Policies (no bucket 'rateios'):
-- 1) SELECT para empresa (apenas sua pasta)
--    USING:   split_part(object_name,'/',1) = auth.email()
-- 2) SELECT para admin:
--    USING:   auth.email() = 'admin@ceasa.com'
-- 3) INSERT/UPDATE (admin):
--    USING:   auth.email() = 'admin@ceasa.com'
--    WITH CHECK: auth.email() = 'admin@ceasa.com'
-- Se você fizer upload via backend com SERVICE ROLE, pode manter o bucket fechado e pular estas policies.
