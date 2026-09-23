// 과제8: 패스키(WebAuthn) 인증 Edge Function
//
// 경로:
//   POST /register/options   { mode: "new"|"add", accountLabel? }   -> 등록용 챌린지 발급
//   POST /register/verify    { challengeId, response, deviceName }  -> 등록 검증 + 계정/패스키 저장
//   POST /login/options      {}                                     -> 로그인용 챌린지 발급 (아이디 없이)
//   POST /login/verify       { challengeId, response }               -> 로그인 검증 + 세션 발급
//   GET  /private-data        (Authorization: Bearer <token>)        -> 로그인한 계정의 비공개 자료
//   GET  /passkeys             (Authorization: Bearer <token>)        -> 로그인한 계정의 패스키 목록
//   DELETE /passkeys/:id       (Authorization: Bearer <token>)        -> 패스키 삭제
//   POST /logout               (Authorization: Bearer <token>)        -> 세션 폐기
//
// 배포: supabase functions deploy auth --no-verify-jwt
// (플랫폼 레벨 JWT 검증을 끄는 것일 뿐, 이 함수 안에서 직접 세션 토큰을 검사합니다.)

import { createClient } from "npm:@supabase/supabase-js@2";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "npm:@simplewebauthn/server@13";

// ---- 이 아래 세 값은 반드시 실제 배포 도메인과 일치해야 합니다 ----
const RP_NAME = "권빈 포트폴리오";
const RP_ID = "kwonbhin.github.io";
const ORIGIN = "https://kwonbhin.github.io";
// -----------------------------------------------------------

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "authorization,content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}
function fail(status: number, message: string) {
  return json({ error: message }, status);
}

// ---- base64url <-> Uint8Array (외부 헬퍼 없이 직접 구현) ----
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlToBytes(b64url: string): Uint8Array {
  const pad = (4 - (b64url.length % 4)) % 4;
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function randomToken(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function getSessionAccountId(req: Request): Promise<string | null> {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const { data, error } = await supabase
    .from("sessions")
    .select("account_id, revoked_at, expires_at")
    .eq("token", token)
    .maybeSingle();
  if (error || !data) return null;
  if (data.revoked_at) return null;
  if (new Date(data.expires_at).getTime() < Date.now()) return null;
  return data.account_id as string;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS });
  }

  const url = new URL(req.url);
  const path =
    url.pathname.replace(/^\/functions\/v1\/auth/, "").replace(/^\/auth/, "") || "/";

  try {
    // ---------- 등록: 옵션 발급 ----------
    if (req.method === "POST" && path === "/register/options") {
      const body = await req.json().catch(() => ({}));
      const mode = body.mode === "add" ? "add" : "new";

      let accountId: string | null = null;
      let excludeCredentials: { id: string; transports?: string[] }[] = [];

      if (mode === "add") {
        accountId = await getSessionAccountId(req);
        if (!accountId) return fail(401, "로그인이 필요합니다.");
        const { data: creds } = await supabase
          .from("credentials")
          .select("id, transports")
          .eq("account_id", accountId);
        excludeCredentials = (creds || []).map((c) => ({
          id: c.id,
          transports: c.transports || undefined,
        }));
      }

      const accountLabel = ((body.accountLabel as string) || "user").slice(0, 60) || "user";

      const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: RP_ID,
        userName: accountLabel,
        userDisplayName: accountLabel,
        attestationType: "none",
        excludeCredentials,
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "preferred",
        },
      });

      const { data: row, error } = await supabase
        .from("challenges")
        .insert({
          challenge: options.challenge,
          type: "registration",
          account_id: accountId,
          meta: { accountLabel },
          expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        })
        .select("id")
        .single();
      if (error) return fail(500, "챌린지 저장에 실패했습니다.");

      return json({ options, challengeId: row.id });
    }

    // ---------- 등록: 검증 ----------
    if (req.method === "POST" && path === "/register/verify") {
      const body = await req.json();
      const { challengeId, response, deviceName } = body;

      // 원자적으로 챌린지를 "사용됨"으로 바꾸면서 가져온다.
      // -> 같은 challengeId로 두 번 verify를 시도하면 두 번째는 행을 못 가져와 거절된다.
      const { data: challenge, error: claimErr } = await supabase
        .from("challenges")
        .update({ used: true })
        .eq("id", challengeId)
        .eq("used", false)
        .eq("type", "registration")
        .select("*")
        .maybeSingle();
      if (claimErr || !challenge) {
        return fail(400, "질문이 유효하지 않거나 이미 사용되었습니다.");
      }
      if (new Date(challenge.expires_at).getTime() < Date.now()) {
        return fail(400, "질문이 만료되었습니다.");
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response,
          expectedChallenge: challenge.challenge,
          expectedOrigin: ORIGIN,
          expectedRPID: RP_ID,
        });
      } catch (e) {
        return fail(400, `등록 검증 실패: ${(e as Error).message}`);
      }
      if (!verification.verified || !verification.registrationInfo) {
        return fail(400, "등록 검증에 실패했습니다.");
      }

      const { credential } = verification.registrationInfo;
      const publicKeyB64 = bytesToBase64Url(credential.publicKey);

      let accountId = challenge.account_id as string | null;
      if (!accountId) {
        const label = (challenge.meta?.accountLabel as string) || "user";
        const { data: account, error: accErr } = await supabase
          .from("accounts")
          .insert({ label })
          .select("id")
          .single();
        if (accErr) return fail(500, "계정 생성에 실패했습니다.");
        accountId = account.id;

        // 비공개 자리에 넣을 더미 데이터 3개 (실제 개인정보 아님)
        await supabase.from("private_items").insert([
          { account_id: accountId, content: `${label}님이 준비 중인 프로젝트 메모 (예시)` },
          { account_id: accountId, content: `${label}님이 지원하려는 곳 목록 (예시)` },
          { account_id: accountId, content: `${label}님의 이번 주 회고 (예시)` },
        ]);
      }

      const { error: credErr } = await supabase.from("credentials").insert({
        id: credential.id,
        account_id: accountId,
        public_key: publicKeyB64,
        counter: credential.counter,
        device_name: ((deviceName as string) || "기기").slice(0, 60),
        transports: credential.transports || [],
      });
      if (credErr) {
        return fail(500, `패스키 저장에 실패했습니다: ${credErr.message}`);
      }

      const { data: accountRow } = await supabase
        .from("accounts")
        .select("id, label")
        .eq("id", accountId)
        .single();

      const token = randomToken();
      await supabase.from("sessions").insert({
        token,
        account_id: accountId,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      });

      return json({ token, account: accountRow });
    }

    // ---------- 로그인: 옵션 발급 (아이디를 먼저 묻지 않는, 패스키 방식) ----------
    if (req.method === "POST" && path === "/login/options") {
      const options = await generateAuthenticationOptions({
        rpID: RP_ID,
        userVerification: "preferred",
      });

      const { data: row, error } = await supabase
        .from("challenges")
        .insert({
          challenge: options.challenge,
          type: "authentication",
          expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        })
        .select("id")
        .single();
      if (error) return fail(500, "챌린지 저장에 실패했습니다.");

      return json({ options, challengeId: row.id });
    }

    // ---------- 로그인: 검증 ----------
    if (req.method === "POST" && path === "/login/verify") {
      const body = await req.json();
      const { challengeId, response } = body;

      const { data: challenge, error: claimErr } = await supabase
        .from("challenges")
        .update({ used: true })
        .eq("id", challengeId)
        .eq("used", false)
        .eq("type", "authentication")
        .select("*")
        .maybeSingle();
      if (claimErr || !challenge) {
        return fail(400, "질문이 유효하지 않거나 이미 사용되었습니다.");
      }
      if (new Date(challenge.expires_at).getTime() < Date.now()) {
        return fail(400, "질문이 만료되었습니다.");
      }

      const credentialId = response.id as string;
      const { data: cred } = await supabase
        .from("credentials")
        .select("*")
        .eq("id", credentialId)
        .maybeSingle();
      if (!cred) return fail(401, "등록되지 않은 패스키입니다.");

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: challenge.challenge,
          expectedOrigin: ORIGIN,
          expectedRPID: RP_ID,
          credential: {
            id: cred.id,
            publicKey: base64UrlToBytes(cred.public_key),
            counter: cred.counter,
            transports: cred.transports || undefined,
          },
        });
      } catch (e) {
        return fail(401, `로그인 검증 실패: ${(e as Error).message}`);
      }
      if (!verification.verified) return fail(401, "로그인 검증에 실패했습니다.");

      await supabase
        .from("credentials")
        .update({ counter: verification.authenticationInfo.newCounter })
        .eq("id", cred.id);

      const { data: accountRow } = await supabase
        .from("accounts")
        .select("id, label")
        .eq("id", cred.account_id)
        .single();

      const token = randomToken();
      await supabase.from("sessions").insert({
        token,
        account_id: cred.account_id,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      });

      return json({ token, account: accountRow });
    }

    // ---------- 비공개 자료 ----------
    if (req.method === "GET" && path === "/private-data") {
      const accountId = await getSessionAccountId(req);
      if (!accountId) return fail(401, "로그인이 필요합니다.");
      // 주의: 쿼리스트링 등으로 다른 accountId가 들어와도 절대 사용하지 않고,
      // 오직 세션 토큰에서 얻은 accountId만 사용한다. (다른 계정 자료 접근 차단)
      const { data, error } = await supabase
        .from("private_items")
        .select("id, content, created_at")
        .eq("account_id", accountId)
        .order("created_at", { ascending: true });
      if (error) return fail(500, "조회에 실패했습니다.");
      return json(data);
    }

    // ---------- 패스키 목록 ----------
    if (req.method === "GET" && path === "/passkeys") {
      const accountId = await getSessionAccountId(req);
      if (!accountId) return fail(401, "로그인이 필요합니다.");
      const { data, error } = await supabase
        .from("credentials")
        .select("id, device_name, public_key, created_at")
        .eq("account_id", accountId)
        .order("created_at", { ascending: true });
      if (error) return fail(500, "조회에 실패했습니다.");
      return json(data);
    }

    // ---------- 패스키 삭제 ----------
    if (req.method === "DELETE" && path.startsWith("/passkeys/")) {
      const accountId = await getSessionAccountId(req);
      if (!accountId) return fail(401, "로그인이 필요합니다.");
      const credId = decodeURIComponent(path.slice("/passkeys/".length));

      const { data: cred } = await supabase
        .from("credentials")
        .select("id, account_id")
        .eq("id", credId)
        .maybeSingle();
      if (!cred || cred.account_id !== accountId) {
        return fail(403, "본인 계정의 패스키만 삭제할 수 있습니다.");
      }
      const { error } = await supabase.from("credentials").delete().eq("id", credId);
      if (error) return fail(500, "삭제에 실패했습니다.");
      return json({ ok: true });
    }

    // ---------- 로그아웃 ----------
    if (req.method === "POST" && path === "/logout") {
      const auth = req.headers.get("authorization") || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
      if (token) {
        await supabase
          .from("sessions")
          .update({ revoked_at: new Date().toISOString() })
          .eq("token", token);
      }
      return json({ ok: true });
    }

    return fail(404, "알 수 없는 경로입니다.");
  } catch (e) {
    console.error(e);
    return fail(500, "서버 오류가 발생했습니다.");
  }
});
