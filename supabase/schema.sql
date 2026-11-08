-- 瀵硅矾 路 澶╄祴娴嬭瘎锛歋upabase schema
-- 鍦?Supabase Dashboard 鈫?SQL Editor 閲屾暣娈垫墽琛屻€?-- 渚濊禆 pgcrypto锛圫upabase 榛樿鍙敤锛夈€?
create extension if not exists pgcrypto;

-- 楠岃瘉鐮佸簱瀛?create table if not exists public.codes (
  code text primary key,
  used boolean not null default false,
  used_at timestamptz,
  order_no text unique,
  allocated_at timestamptz,
  note text,
  created_at timestamptz not null default now()
);

-- 鐧诲綍浼氳瘽
create table if not exists public.sessions (
  token text primary key,
  code text not null references public.codes(code),
  created_at timestamptz not null default now(),
  last_seen timestamptz not null default now()
);
create index if not exists idx_sessions_code on public.sessions(code);

-- 璁㈠崟 / 鑷姪棰嗗彇
create table if not exists public.orders (
  order_no text primary key,
  secret_hash text,
  code text not null unique references public.codes(code),
  status text not null default 'issued',
  created_at timestamptz not null default now(),
  claimed_at timestamptz
);

-- 鑷姩鍙戣揣 API Key锛堝彧瀛?hash锛?create table if not exists public.app_settings (
  name text primary key,
  value text not null
);

-- RLS锛氳〃涓嶅厑璁?anon 鐩存帴璇诲啓锛屽彧鑳借蛋涓嬮潰鐨?security definer 鍑芥暟
alter table public.codes enable row level security;
alter table public.sessions enable row level security;
alter table public.orders enable row level security;
alter table public.app_settings enable row level security;

revoke all on table public.codes from anon, authenticated;
revoke all on table public.sessions from anon, authenticated;
revoke all on table public.orders from anon, authenticated;
revoke all on table public.app_settings from anon, authenticated;

-- 鐧诲綍锛氶獙璇佺爜涓€鐮佷竴浜?create or replace function public.login_with_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_input text;
  v_code text;
  v_token text;
begin
  v_input := upper(regexp_replace(coalesce(p_code, ''), '\s', '', 'g'));
  if length(v_input) < 6 then
    return jsonb_build_object('ok', false, 'error', 'invalid_format');
  end if;

  update public.codes
     set used = true, used_at = now()
   where code = v_input and used = false
  returning code into v_code;

  if v_code is null then
    if exists (select 1 from public.codes where code = v_input) then
      return jsonb_build_object('ok', false, 'error', 'used');
    end if;
    return jsonb_build_object('ok', false, 'error', 'invalid');
  end if;

  v_token := encode(gen_random_bytes(24), 'hex');
  insert into public.sessions(token, code) values (v_token, v_code);
  return jsonb_build_object('ok', true, 'token', v_token);
end;
$$;

-- 浼氳瘽鏍￠獙
create or replace function public.check_session(p_token text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  update public.sessions
     set last_seen = now()
   where token = p_token;
  return found;
end;
$$;

-- 涔板鑷姪棰嗗彇锛氳鍗曞彿 + 鎵嬫満灏惧彿 4 浣?create or replace function public.claim_order(p_order_no text, p_secret text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_order text;
  v_secret text;
  v_hash text;
  v_row public.orders%rowtype;
begin
  v_order := upper(regexp_replace(coalesce(p_order_no, ''), '\s', '', 'g'));
  if length(v_order) < 4 then
    return jsonb_build_object('ok', false, 'error', 'invalid_order');
  end if;

  select * into v_row from public.orders where order_no = v_order;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;

  if v_row.secret_hash is not null then
    v_secret := right(regexp_replace(coalesce(p_secret, ''), '\D', '', 'g'), 4);
    v_hash := encode(digest(v_order || ':' || v_secret, 'sha256'), 'hex');
    if v_hash <> v_row.secret_hash then
      return jsonb_build_object('ok', false, 'error', 'secret_mismatch');
    end if;
  end if;

  if v_row.status = 'issued' then
    update public.orders
       set status = 'claimed', claimed_at = now()
     where order_no = v_order;
  end if;

  return jsonb_build_object('ok', true, 'code', v_row.code);
end;
$$;

-- 鑷姩鍙戣揣 API锛堢粰闆嗙畝浜?褰卞垁/RPA 璋冪敤锛?create or replace function public.auto_delivery(p_key text, p_order_no text, p_secret text default null)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_expected text;
  v_order text;
  v_secret text;
  v_hash text;
  v_code text;
  v_existing text;
begin
  select value into v_expected
    from public.app_settings
   where name = 'auto_delivery_key_hash';

  if v_expected is null
     or encode(digest(coalesce(p_key, ''), 'sha256'), 'hex') <> v_expected then
    return jsonb_build_object('ok', false, 'error', 'unauthorized');
  end if;

  v_order := upper(regexp_replace(coalesce(p_order_no, ''), '\s', '', 'g'));
  if length(v_order) < 4 then
    return jsonb_build_object('ok', false, 'error', 'invalid_order');
  end if;

  select code into v_existing from public.orders where order_no = v_order;
  if v_existing is not null then
    return jsonb_build_object('ok', true, 'code', v_existing, 'existed', true);
  end if;

  select code into v_code
    from public.codes
   where used = false and order_no is null
   order by created_at
   limit 1
   for update skip locked;

  if v_code is null then
    return jsonb_build_object('ok', false, 'error', 'out_of_stock');
  end if;

  update public.codes
     set order_no = v_order, allocated_at = now()
   where code = v_code and order_no is null;

  v_secret := right(regexp_replace(coalesce(p_secret, ''), '\D', '', 'g'), 4);
  v_hash := case when length(v_secret) > 0
                 then encode(digest(v_order || ':' || v_secret, 'sha256'), 'hex')
                 else null end;

  insert into public.orders(order_no, secret_hash, code, status)
  values (v_order, v_hash, v_code, 'issued');

  return jsonb_build_object('ok', true, 'code', v_code, 'existed', false);
end;
$$;

-- 鍙厑璁稿尶鍚嶈皟鐢ㄨ繖浜涘嚱鏁帮紱琛ㄦ湰韬粛鐒朵笉鍙洿鎺ヨ闂?grant execute on function public.login_with_code(text) to anon;
grant execute on function public.check_session(text) to anon;
grant execute on function public.claim_order(text, text) to anon;
grant execute on function public.auto_delivery(text, text, text) to anon;

-- 鑷姩鍙戣揣 Key锛氭妸 CHANGE_ME_TO_A_LONG_RANDOM_STRING 鎹㈡垚浣犺嚜宸辩殑瀵嗛挜鍚庢墽琛?-- insert into public.app_settings(name, value)
-- values ('auto_delivery_key_hash', encode(digest('CHANGE_ME_TO_A_LONG_RANDOM_STRING', 'sha256'), 'hex'));

