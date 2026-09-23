-- 과제8: 패스키 인증용 스키마
-- 비밀번호 컬럼은 어디에도 없습니다. credentials.public_key 는 "공개키"만 저장합니다.

create extension if not exists pgcrypto;

-- 계정: 이메일/비밀번호 없이, 패스키로만 식별되는 사람 단위
create table if not exists accounts (
  id uuid primary key default gen_random_uuid(),
  label text not null,                 -- 계정을 알아보기 위한 이름 (예: "권빈", "테스트B")
  created_at timestamptz not null default now()
);

-- 패스키(자격증명): 공개키만 저장. 개인키는 사용자 기기 밖으로 나가지 않으므로 여기 없음.
create table if not exists credentials (
  id text primary key,                 -- WebAuthn credential ID (base64url)
  account_id uuid not null references accounts(id) on delete cascade,
  public_key text not null,            -- 공개키 (base64url 인코딩)
  counter bigint not null default 0,   -- 서명 카운터 (복제 탐지용)
  device_name text not null,           -- 사람이 붙인 기기 이름
  transports text[],
  created_at timestamptz not null default now()
);

-- 챌린지: 등록/로그인용 일회용 질문. used=true 가 되면 재사용 불가.
create table if not exists challenges (
  id uuid primary key default gen_random_uuid(),
  challenge text not null,
  type text not null check (type in ('registration','authentication')),
  account_id uuid references accounts(id) on delete cascade, -- 로그인 상태에서 패스키를 "추가" 등록할 때만 채워짐
  meta jsonb not null default '{}'::jsonb,
  used boolean not null default false,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

-- 세션: 로그인 성공 후 발급하는 불투명 토큰(랜덤 문자열). 비밀번호도, JWT도 아님.
create table if not exists sessions (
  token text primary key,
  account_id uuid not null references accounts(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz
);

-- 비공개 자료: 만들어 넣은 더미 콘텐츠. 실제 개인정보 넣지 않음.
create table if not exists private_items (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  content text not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_credentials_account on credentials(account_id);
create index if not exists idx_sessions_account on sessions(account_id);
create index if not exists idx_private_items_account on private_items(account_id);

-- RLS 켜두고 정책은 하나도 만들지 않음 -> anon/authenticated 키로는 이 테이블들에 직접 접근 불가.
-- 오직 Edge Function 안에서 쓰는 service_role 키만 RLS를 우회해 접근할 수 있음.
-- (이게 T08-C16/C17: 로그인 안 하고 직접 요청하면 401/403으로 거절되는 근거)
alter table accounts enable row level security;
alter table credentials enable row level security;
alter table challenges enable row level security;
alter table sessions enable row level security;
alter table private_items enable row level security;
