// magpie-codearts: an OpenCode provider plugin for magpie.
//
// It signs in to Huawei Cloud CodeArts the way the CodeArts CLI does —
// CodeArts_Tui's OAuth, PKCE with a DPoP proof against the STS token
// endpoint, a local callback server — and serves the account's models
// (GLM, OpenPangu) as an OpenAI-compatible provider. magpie's gateway
// exposes every provider on its OpenAI-compatible API, so the plugin
// both brings CodeArts' models into magpie and reverse-proxies them out.
//
// The chat wire is OpenAI-compatible: POST {inferhub}/api/v2/chat/completions
// signed with the account's temporary AK/SK (Huawei Cloud's
// SDK-HMAC-SHA256 scheme, the same signer the CLI uses) plus the x-ot-*
// trace headers the CLI sends. The OAuth flow hands out
// {access_key_id, secret_access_key, security_token} that live about an
// hour; magpie renews them through auth.refresh with the kept refresh
// token, exactly as the CLI refreshes on its own.

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto"
import { networkInterfaces } from "node:os"

const PROVIDER = "codearts"
const INFERHUB = "https://snap-access.cn-north-4.myhuaweicloud.com"
// chat lives under /api/v2 on the inferhub host (the CLI's own base for
// codemate ends in /api/v2/, and its normalizer appends the suffix); the
// other services (agent-center, snap-manager) sit at the root
const CHAT_BASE = INFERHUB + "/api/v2"
const STS = "https://sts.cn-north-4.myhuaweicloud.com"
const PORTAL = "https://codearts.huaweicloud.com/portal"
const TOKENS = STS + "/v1/oauth2/tokens"
const TICKET = INFERHUB + "/snap-manager/v1/login/ticket"
const CURRENT_USER = INFERHUB + "/snap-manager/v1/current/user"
// the account's credit allowance, read with the same signed GETs
const STATISTICS = INFERHUB + "/snap-manager/v1/statistics/plugin"
const USERAGENTS = INFERHUB + "/v1/agent-center/agents/useragents"
const AGENT_DETAIL = INFERHUB + "/v1/agent-center/agents/detail"
const CLIENT_ID = "CodeArts_Tui"
const CLI_VERSION = "26.9.12" // the CLI whose sign-in and headers this makes
const LANGUAGE = process.env.CODEARTS_CLI_LANGUAGE ?? "zh-cn"
const CALLBACK_TIMEOUT = 5 * 60_000 // the CLI's own wait for the browser
// the agent whose models the CLI lists for an account that names none
const DEFAULT_AGENT = "a8bcb36232554267a5142361cc25a393"

// CodeArts' models before the account's own list is read. The keys are
// what the chat endpoint takes in `model`; the names are what CodeArts
// shows — the CLI's own table, drawn from the same fetch this plugin
// makes, names them this way. All of them think.
const MODELS = [
  { key: "GLM-5.2", name: "GLM-5.2", context: 202752, input: 196608, output: 131072, reasoning: true },
  { key: "glm-5.2-sft-harmony", name: "GLM-5.2-ArkTS-SPARK", context: 202752, input: 196608, output: 131072, reasoning: true },
  { key: "openpangu-2.0-pro", name: "OpenPangu-2.0-Pro", context: 524288, input: 512000, output: 131072, reasoning: true },
  { key: "openpangu-2.0-flash", name: "OpenPangu-2.0-Flash", context: 524288, input: 512000, output: 131072, reasoning: true },
]

const STATUS_TEXT = { 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
  408: "Request Timeout", 429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
  504: "Gateway Timeout" }

const uuid = () => randomUUID().replace(/-/g, "") // the CLI's trace ids carry no dashes
const sha256hex = (s) => createHash("sha256").update(s).digest("hex")
const b64url = (b) => Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")

function localIP() {
  try {
    for (const xs of Object.values(networkInterfaces())) for (const x of xs ?? []) if (x.family === "IPv4" && !x.internal) return x.address
  } catch {}
  return "127.0.0.1"
}

// ---- Huawei Cloud AK/SK signing (the CLI's signer, @huaweicloud/hcloud-sdk) ----
//
// Authorization: SDK-HMAC-SHA256 Access=ak, SignedHeaders=…, Signature=…
// over a canonical request of method, URI (each segment URL-encoded, a
// trailing slash appended), sorted query, lower-cased sorted headers
// (host and X-Sdk-Date among them), and the SHA-256 of JSON.stringify(body)
// — an empty body's digest when there is none.

const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Huawei's URL encoding: A-Z a-z 0-9 - _ . ~ pass, everything else %XX.
const hwUrlEncode = (s) =>
  encodeURIComponent(String(s)).replace(/[!*'()]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase())

function canonicalURI(pathname) {
  const out = pathname.split("/").map(hwUrlEncode).join("/")
  return out.endsWith("/") ? out : out + "/"
}

function canonicalQuery(url) {
  const q = {}
  for (const [k, v] of url.searchParams.entries()) k in q ? (Array.isArray(q[k]) ? q[k].push(v) : (q[k] = [q[k], v])) : (q[k] = v)
  const parts = []
  for (const k of Object.keys(q).sort()) {
    if (Array.isArray(q[k])) for (const v of [...q[k]].sort()) parts.push(`${hwUrlEncode(k)}=${hwUrlEncode(v)}`)
    else parts.push(`${hwUrlEncode(k)}=${hwUrlEncode(q[k])}`)
  }
  return parts.join("&")
}

function sdkDate() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, "0")
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`
}

// sign builds the headers that carry `headers` to `url` signed with ak/sk.
// `data` is the request body as a value (hashed as JSON.stringify of it).
function sign({ method, url, headers, ak, sk, data }) {
  const h = {}
  for (const [k, v] of new Headers(headers)) h[k.toLowerCase()] = String(v)
  if ((h["content-type"] ?? "").includes("multipart/form-data")) delete h["content-type"]
  const date = sdkDate()
  h["x-sdk-date"] = date
  h["host"] = url.host
  const keys = Object.keys(h).sort()
  const signedHeaders = keys.join(";")
  const canonicalHeaders = keys.map((k) => `${k}:${h[k]}\n`).join("")
  const payload = data === undefined || data === null ? EMPTY_BODY_SHA256 : sha256hex(JSON.stringify(data))
  const canonical = [method.toUpperCase(), canonicalURI(url.pathname), canonicalQuery(url), canonicalHeaders, signedHeaders, payload].join("\n")
  const toSign = ["SDK-HMAC-SHA256", date, sha256hex(canonical)].join("\n")
  const signature = createHmac("sha256", sk).update(toSign).digest("hex")
  const out = new Headers()
  for (const k of keys) if (k !== "host") out.set(k, h[k])
  out.set("Authorization", `SDK-HMAC-SHA256 Access=${ak}, SignedHeaders=${signedHeaders}, Signature=${signature}`)
  return out
}

// a signed GET/POST of JSON to one of CodeArts' own endpoints
async function callCodearts(url, { method = "GET", body, agentType, creds } = {}) {
  const h = { "Content-Type": "application/json", Accept: "application/json", "X-Language": LANGUAGE }
  if (agentType) h["Agent-Type"] = agentType
  if (creds.security_token) h["X-Security-token"] = creds.security_token
  const u = new URL(url)
  const headers = sign({ method, url: u, headers: h, ak: creds.access_key_id, sk: creds.secret_access_key, data: body })
  const res = await fetch(u, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  if (!res.ok) throw new Error(`${u.pathname}: ${STATUS_TEXT[res.status] ?? res.status} ${(await res.text().catch(() => "")).slice(0, 200)}`)
  return res.json()
}

// ---- DPoP proofs (the STS token endpoints want one) ----

async function dpopKeyPair() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  return { privateKeyJwk: await crypto.subtle.exportKey("jwk", privateKey), publicKeyJwk: await crypto.subtle.exportKey("jwk", publicKey) }
}

async function dpopProof(pair, htu) {
  const key = await crypto.subtle.importKey("jwk", pair.privateKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
  const header = { alg: "ES256", typ: "dpop+jwt", jwk: pair.publicKeyJwk }
  const payload = { htm: "POST", htu, iat: Math.floor(Date.now() / 1000), jti: randomBytes(16).toString("hex") }
  const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(unsigned))
  return `${unsigned}.${b64url(sig)}`
}

// ---- OAuth: CodeArs_Tui's flow, PKCE + DPoP, a local callback server ----

// exchangeCode trades the browser's authorization code for credentials.
// The answer carries {credentials, refresh_token}; the credentials hold
// access_key_id / secret_access_key / security_token / expiration.
async function exchangeCode(code, verifier, redirectUri, pair) {
  const res = await fetch(TOKENS, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", DPoP: await dpopProof(pair, TOKENS) },
    body: new URLSearchParams({ client_id: CLIENT_ID, code, code_verifier: verifier, grant_type: "authorization_code", redirect_uri: redirectUri }).toString(),
  })
  if (!res.ok) throw new Error(`token exchange failed: ${(await res.json().catch(() => ({}))).error_description ?? res.statusText}`)
  const env = await res.json()
  if (!env?.credentials?.access_key_id) throw new Error("token exchange gave no credentials")
  return env
}

// pollTicket trades the portal's one-time secret for credentials. It
// hands out no refresh token: the sign-in lasts as long as the temporary
// credentials do, then the account signs in again.
async function pollTicket(ticketId, secret) {
  const url = `${TICKET}?${new URLSearchParams({ ticket_id: ticketId, secret })}`
  for (let i = 1; i <= 10; i++) {
    await new Promise((ok) => setTimeout(ok, 1000))
    const res = await fetch(url, { headers: { Accept: "application/json" } })
    if (res.ok) {
      const w = await res.json()
      const c = w?.credential
      if (!c?.access) throw new Error("ticket exchange gave no credentials")
      return { credentials: { access_key_id: c.access, secret_access_key: c.secret, security_token: c.securitytoken, expiration: c.expires_at }, refresh_token: "" }
    }
  }
  throw new Error("ticket exchange failed after 10 attempts")
}

// currentUser names the account (domain and user ids), as the CLI keeps it.
async function currentUser(creds) {
  try {
    return await callCodearts(CURRENT_USER, { creds })
  } catch {
    return null
  }
}

// ---- the account's allowance (magpie's usage card) ----

// the credit buckets CodeArts reports, in the card's words
const CREDIT_METRIC_LABELS = {
  usageTotalPackageCredit: "总积分",
  usageBasicPackageCredit: "基础积分包",
  usageOnDemandPackageCredit: "按需积分包",
  usageBonusPackageCredit: "赠送积分包",
}
const TOTAL_CREDIT_METRIC = "usageTotalPackageCredit"

// compact credit counts: 12345 → "1.2万", 0.01 stays "0.01"
function formatCredit(n) {
  const v = Math.max(0, Number.isFinite(n) ? n : 0)
  if (v >= 1e8) return `${(v / 1e8).toFixed(1)}亿`
  if (v >= 1e4) return `${(v / 1e4).toFixed(1)}万`
  return Number.isInteger(v) ? String(v) : String(Number(v.toFixed(2)))
}

const clampPercent = (n) => Math.min(100, Math.max(0, n))
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : Number(v) || 0)

// usageFromStatistics maps snap-manager's statistics/plugin answer to
// magpie's auth.usage shape: the package names the plan, and the credit
// buckets become windows, the package total first.
function usageFromStatistics(raw) {
  let data = raw
  if (raw && typeof raw.code === "number") {
    if (raw.code !== 0) return { error: raw.message || raw.msg || `CodeArts code ${raw.code}`, windows: [] }
    data = raw.data
  }
  if (!data || typeof data !== "object") return { error: "CodeArts answered nothing", windows: [] }
  const pkg = data.package && typeof data.package === "object" ? data.package : {}
  const plan = pkg.package_name_cn || pkg.package_name_en || pkg.spec_code || ""
  const metrics = Array.isArray(data.metrics) ? data.metrics : []
  const windows = []
  for (const item of metrics) {
    if (!item || typeof item !== "object") continue
    const name = CREDIT_METRIC_LABELS[item.name]
    if (!name) continue
    const limit = num(item.package_credit_amount)
    const remain = num(item.package_credit_remain)
    if (limit <= 0 && remain <= 0) continue // an empty bucket says nothing
    const used = item.package_credit_used != null ? num(item.package_credit_used) : Math.max(0, limit - remain)
    windows.push({
      name,
      used: limit > 0 ? clampPercent((used / limit) * 100) : 0,
      display: `${formatCredit(used)} / ${formatCredit(limit)}`,
      amount: used,
      limit,
      unit: "credits",
    })
  }
  // the package total on top, then the buckets that make it up
  const totalLabel = CREDIT_METRIC_LABELS[TOTAL_CREDIT_METRIC]
  windows.sort((a, b) => (a.name === totalLabel ? -1 : b.name === totalLabel ? 1 : 0))
  if (windows.length > 0) return { plan: plan || undefined, signIn: "kept", windows }
  return { plan: plan || undefined, windows, error: "该账号无积分额度" }
}

// accountName is the account as CodeArts names it: sign-ins made before
// this plugin stored the name kept the whole current/user answer there.
function accountName(auth) {
  const id = typeof auth?.accountId === "string" ? auth.accountId.trim() : ""
  if (!id) return ""
  if (!id.startsWith("{")) return id
  try {
    const u = JSON.parse(id)
    return u?.user_name || u?.domain_name || u?.user_id || ""
  } catch {
    return ""
  }
}

// accountHeader is the id part x-agent-user-account carries; an accountId
// stored as the current/user answer keeps its id.
function accountHeader(accountId) {
  const id = typeof accountId === "string" ? accountId.trim() : ""
  if (!id) return ""
  if (!id.startsWith("{")) return id
  try {
    const u = JSON.parse(id)
    return u?.user_id || u?.domain_id || ""
  } catch {
    return ""
  }
}

// refreshTokens renews the credentials with the kept refresh token. A
// refresh token spent or turned away fails 400/401: the account is asked
// to sign in again.
async function refreshTokens(refreshToken, pair, accountId) {
  const res = await fetch(TOKENS, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", DPoP: await dpopProof(pair, TOKENS), "x-agent-user-account": accountHeader(accountId) },
    body: new URLSearchParams({ client_id: CLIENT_ID, refresh_token: refreshToken, grant_type: "refresh_token" }).toString(),
  })
  if (!res.ok) {
    const e = new Error(`token refresh failed: ${(await res.json().catch(() => ({}))).error_description ?? res.statusText}`)
    if (res.status === 400 || res.status === 401) e.signIn = "expired"
    throw e
  }
  const env = await res.json()
  if (!env?.credentials?.access_key_id) throw new Error("token refresh gave no credentials")
  return env
}

// authorize starts the sign-in: a local server for the browser to come
// back to, and CodeArts' page for it to sign in on.
function authorize(log) {
  const verifier = randomBytes(64).toString("hex")
  const challenge = b64url(createHash("sha256").update(verifier).digest())
  const ticketId = randomBytes(32).toString("hex").slice(0, 64)
  let resolve, reject
  const finished = new Promise((ok, err) => ((resolve = ok), (reject = err)))
  const timer = setTimeout(() => reject(new Error("sign-in timed out; start again")), CALLBACK_TIMEOUT)
  const done = (p) => {
    clearTimeout(timer)
    server.stop(true)
    p.then(resolve, reject)
  }
  const page = (ok, redirect) =>
    Response.redirect(redirect || `${PORTAL}/login?login_succeed=${ok}&locale=${LANGUAGE}`, 307)
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const u = new URL(req.url)
      if (u.pathname !== "/oauth/callback") return new Response("Not found", { status: 404 })
      const code = u.searchParams.get("code")
      const secret = u.searchParams.get("secret")
      const redirect = u.searchParams.get("redirect")
      const pair = await dpopKeyPair()
      if (secret && redirect) {
        done(pollTicket(ticketId, secret).then((env) => ({ ...env, pair })))
        return page(true, redirect)
      }
      if (code) {
        try {
          const env = await exchangeCode(code, verifier, `http://127.0.0.1:${server.port}/oauth/callback`, pair)
          done(Promise.resolve({ ...env, pair }))
          return page(true, redirect)
        } catch (e) {
          log(`sign-in exchange failed: ${e?.message ?? e}`)
          done(Promise.reject(e))
          return page(false, redirect)
        }
      }
      return page(false, redirect)
    },
  })
  const url = `${PORTAL}/authorize?${new URLSearchParams({
    locale: LANGUAGE,
    client_id: CLIENT_ID,
    port: String(server.port),
    code_challenge: challenge,
    code_challenge_method: "SHA-256",
    ticket_id: ticketId,
  })}`
  return {
    url,
    instructions: "Sign in to Huawei Cloud CodeArts in the browser that opened; this finishes on its own.",
    method: "auto",
    async callback() {
      try {
        const { credentials, refresh_token: refreshToken, pair } = await finished
        const user = await currentUser(credentials)
        return {
          type: "success",
          refresh: refreshToken ?? "",
          access: JSON.stringify({ ...credentials, dpop_key_pair: pair }),
          expires: Date.parse(credentials.expiration) || Date.now() + 3600_000,
          // magpie shows this as the account's name; the whole user record
          // made every card and login list show a JSON blob
          accountId: user ? (user.user_name || user.domain_name || user.user_id || "") : "",
        }
      } catch (e) {
        return { type: "failed", error: e?.message ?? String(e) }
      }
    },
  }
}

// ---- the account's models ----

// credsOf reads the sign-in magpie keeps: OpenCode's OAuth shape, the
// access field holding the credentials JSON (the CLI stores the same in
// its own auth.json).
function credsOf(auth) {
  if (!auth || auth.type !== "oauth" || typeof auth.access !== "string") return null
  try {
    const c = JSON.parse(auth.access)
    return c?.access_key_id && c?.secret_access_key ? c : null
  } catch {
    return null
  }
}

const entry = (m) => ({
  id: m.key,
  name: m.name,
  reasoning: !!m.reasoning,
  tool_call: true,
  attachment: false,
  modalities: { input: ["text"], output: ["text"] },
  limit: { context: m.context || 0, input: m.input || 0, output: m.output || 0 },
  cost: { input: 0, output: 0, cache_read: 0, cache_write: 0 },
})

const STATIC_MODELS = Object.fromEntries(MODELS.map((m) => [m.key, entry(m)]))

// fetchModels lists what CodeArts serves the account: the agent-center's
// useragents pick the account's agent, its detail names its models.
async function fetchModels(creds) {
  const listEnv = await callCodearts(`${USERAGENTS}?offset=0&limit=100`, { agentType: "AgentCenter", creds })
  // both answers carry their payload at the top level: {total, agents} and
  // the agent's own record, no wrapping data field
  const list = listEnv?.agents ?? []
  const pick = list.find((a) => a && (a.agent_id === DEFAULT_AGENT || a.original_id === DEFAULT_AGENT)) ?? list.find((a) => a?.agent_id)
  const detail = await callCodearts(`${AGENT_DETAIL}?agent_id=${encodeURIComponent(pick?.agent_id ?? DEFAULT_AGENT)}`, { agentType: "AgentCenter", creds })
  const ms = detail?.gpts?.models ?? []
  const out = []
  for (const m of ms) {
    const p = m?.model_parameters
    if (!p?.model_id) continue
    out.push({
      key: p.model_id,
      name: m.model_name || m.model_alias || p.model_id,
      context: Number(p.context_window) || 0,
      input: Number(p.input_length) || 0,
      output: Number(p.max_tokens) || 131072,
      // the vendor's list leaves thinking_type null, but its API streams a
      // reasoning_content for every model of it, GLM and pangu alike
      reasoning: true,
    })
  }
  return out
}

// ---- chat: OpenAI-compatible, signed as the CLI signs it ----

function chatHeaders(model, creds) {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    "X-Security-token": creds.security_token || "",
    "x-ot-trace-id": uuid(),
    "x-ot-span-id": uuid(),
    "x-snap-traceid": uuid(),
    "x-ot-session-id": uuid(),
    "x-ot-parent-session-id": "",
    "user-session-id": uuid(),
    "x-ot-function": "agent-tui",
    "X-Language": LANGUAGE,
    "user-msg-id": "",
    "created-time": "",
    "model-id": model,
    "model-name": encodeURIComponent(model),
    "x-ot-client-type": "CLI",
    "x-ot-client-version": CLI_VERSION,
    "client-ip": localIP(),
  }
}

// ---- the plugin ------------------------------------------------------------------

export async function CodeArtsPlugin({ client }) {
  const log = (message) => {
    try {
      client?.app?.log?.({ body: { service: "codearts", level: "error", message } })
    } catch {}
  }
  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      const was = cfg.provider[PROVIDER] ?? {}
      cfg.provider[PROVIDER] = {
        name: "CodeArts",
        npm: "@ai-sdk/openai-compatible",
        api: CHAT_BASE,
        ...was,
        models: { ...STATIC_MODELS, ...(was.models ?? {}) },
      }
      // this file is also the plugin this package's own agent module
      // (codearts.agent.js) points CodeArts at, to wire the CLI onto
      // magpie's models: CodeArts recomputes enabled_providers — the
      // whitelist its providers must be on — at every start and drops
      // what the config file said, so "magpie" is put back here
      if (Array.isArray(cfg.enabled_providers) && !cfg.enabled_providers.includes("magpie")) {
        cfg.enabled_providers = [...cfg.enabled_providers, "magpie"]
      }
    },
    provider: {
      id: PROVIDER,
      // CodeArts' own list for the account; the table above stands in
      // when it can't be had, and magpie keeps the list it was told last
      async models(provider, { auth } = {}) {
        const creds = credsOf(auth)
        if (!creds) return provider.models
        try {
          const live = await fetchModels(creds)
          if (!live.length) throw new Error("CodeArts named no models")
          return Object.fromEntries(live.map((m) => [m.key, entry(m)]))
        } catch (e) {
          log(`models fetch failed, table stands in: ${e?.message ?? e}`)
          const out = { ...STATIC_MODELS }
          out[Symbol.for("magpie.fellBack")] = true
          return out
        }
      },
    },
    auth: {
      provider: PROVIDER,
      // the credentials live about an hour; magpie renews them 5 minutes
      // before they run out, as the CLI renews its own
      refreshLead: 5 * 60_000,
      async loader(getAuth, provider) {
        if (!credsOf(await getAuth())) return {}
        return {
          baseURL: CHAT_BASE,
          apiKey: "codearts", // the fetch below carries the real sign-in
          async fetch(input, init) {
            const creds = credsOf(await getAuth())
            if (!creds) throw new Error("not signed in to CodeArts")
            const url = input instanceof Request ? input.url : String(input)
            const opts = input instanceof Request
              ? { method: input.method, headers: input.headers, body: input.body, signal: input.signal, duplex: "half", ...init }
              : { ...init }
            const method = opts.method || "POST"
            let bodyText
            if (opts.body != null && opts.body !== "") bodyText = typeof opts.body === "string" ? opts.body : await new Response(opts.body).text()
            let model = ""
            try {
              model = JSON.parse(bodyText)?.model ?? ""
            } catch {}
            const u = new URL(url)
            let data = null
            try {
              data = bodyText != null ? JSON.parse(bodyText) : null
            } catch {}
            const headers = sign({ method, url: u, headers: chatHeaders(model, creds), ak: creds.access_key_id, sk: creds.secret_access_key, data })
            const res = await fetch(u, { method, headers, body: bodyText, signal: opts.signal })
            if (!res.ok) {
              const text = await res.text().catch(() => "")
              log(`chat ${res.status}: ${text.slice(0, 300)}`)
              return new Response(text, { status: res.status, statusText: res.statusText, headers: { "content-type": res.headers.get("content-type") ?? "application/json" } })
            }
            return res
          },
        }
      },
      // renew the sign-in with the kept refresh token; a refresh token
      // CodeArts turned away for good asks for a sign-in again
      async refresh(auth) {
        const creds = credsOf(auth)
        const pair = creds?.dpop_key_pair
        if (!auth?.refresh || !pair) {
          const e = new Error("CodeArts sign-in cannot be renewed (no refresh token); sign in again")
          e.signIn = "expired"
          throw e
        }
        const env = await refreshTokens(auth.refresh, pair, auth.accountId || "")
        return {
          access: JSON.stringify({ ...env.credentials, dpop_key_pair: pair }),
          refresh: env.refresh_token ?? auth.refresh,
          expires: Date.parse(env.credentials.expiration) || Date.now() + 3600_000,
        }
      },
      // magpie's own hook: how much of the plan is left, as CodeArts'
      // statistics page reads it. The package names the plan, the credit
      // buckets are the windows; magpie shows the account's name beside it.
      async usage(getAuth) {
        const auth = await getAuth()
        const creds = credsOf(auth)
        if (!creds) return { error: "not signed in", windows: [] }
        try {
          const raw = await callCodearts(STATISTICS, { creds, agentType: "PromptCenter" })
          const out = usageFromStatistics(raw)
          const user = accountName(auth)
          if (user) out.user = user
          return out
        } catch (e) {
          return { error: e?.message ?? String(e), windows: [] }
        }
      },
      methods: [
        {
          type: "oauth",
          label: "华为云 CodeArts（CodeArts CLI 同款登录）",
          authorize: () => authorize(log),
        },
      ],
    },
  }
}

// for tests — a function, not an object: CodeArts calls every export of a
// plugin file, and one that isn't callable silently disables the whole file
export function _internal() {
  return { sign, canonicalQuery, canonicalURI, hwUrlEncode, exchangeCode, pollTicket, refreshTokens, currentUser, fetchModels, credsOf, entry, chatHeaders, usageFromStatistics, accountName, accountHeader, MODELS }
}
