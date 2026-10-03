import express from "express";
import pg from "pg";
import crypto from "node:crypto";

const URL_DB = process.env.DATABASE_URL;
if (!URL_DB) { console.error("Defina DATABASE_URL"); process.exit(1); }
if (!process.env.ADMIN_PASSWORD) console.error("ATENÇÃO: defina ADMIN_PASSWORD, senão ninguém consegue entrar no painel.");
const pool = new pg.Pool({ connectionString: URL_DB, ssl: /localhost|127\.0\.0\.1/.test(URL_DB) ? false : { rejectUnauthorized: false } });
await pool.query(`CREATE TABLE IF NOT EXISTS resultados(id SERIAL PRIMARY KEY, criado TIMESTAMPTZ DEFAULT now(), dados JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS config(id INT PRIMARY KEY, dados JSONB NOT NULL);`);

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use((_, res, next) => { res.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin" }); next(); });

/* ---- sessão do admin: cookie assinado (HMAC), HttpOnly ---- */
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const sign = v => crypto.createHmac("sha256", SECRET).update(v).digest("hex");
const isAdm = req => {
  const c = (req.headers.cookie || "").match(/(?:^|; )adm=([^;]+)/)?.[1];
  if (!c) return false;
  const [t, s] = c.split(".");
  const e = sign(t || "");
  return !!s && s.length === e.length && +t > Date.now() && crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e));
};
const auth = (req, res, next) => isAdm(req) ? next() : res.status(401).json({ erro: "Não autorizado" });

const tries = new Map();
const limited = (ip, max, ms) => {
  const n = tries.get(ip) || { c: 0, t: Date.now() };
  if (Date.now() - n.t > ms) { n.c = 0; n.t = Date.now(); }
  n.c++; tries.set(ip, n); return n.c > max;
};

app.post("/api/login", (req, res) => {
  if (limited("L" + req.ip, 8, 15 * 60e3)) return res.status(429).json({ erro: "Muitas tentativas. Aguarde alguns minutos." });
  const a = Buffer.from(String(req.body?.senha || "")), b = Buffer.from(process.env.ADMIN_PASSWORD || "");
  if (!b.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ erro: "Senha incorreta" });
  const t = String(Date.now() + 12 * 3600e3);
  res.cookie("adm", `${t}.${sign(t)}`, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 12 * 3600e3, path: "/" });
  res.json({ ok: true });
});
app.post("/api/logout", (_, res) => { res.clearCookie("adm", { path: "/" }); res.json({ ok: true }); });
app.get("/api/me", (req, res) => res.json({ adm: isAdm(req) }));

/* ---- configuração do formulário (modelos, perguntas, descontos) ---- */
app.get("/api/config", async (_, res) => {
  const r = await pool.query("SELECT dados FROM config WHERE id=1");
  res.json(r.rows[0]?.dados ?? null);
});
app.put("/api/admin/config", auth, async (req, res) => {
  const c = req.body;
  if (!c || typeof c.ativo !== "string" || typeof c.m !== "object" || !c.m[c.ativo]) return res.status(400).json({ erro: "Configuração inválida" });
  await pool.query("INSERT INTO config(id,dados) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET dados=EXCLUDED.dados", [c]);
  res.json({ ok: true });
});

/* ---- resultados ---- */
const S = (v, n = 200) => String(v ?? "").slice(0, n);
const N = (v, a, b) => Math.min(b, Math.max(a, Number(v) || 0));
const A = v => (Array.isArray(v) ? v : []).slice(0, 30).map(x => S(x));
app.post("/api/resultados", async (req, res) => {
  if (limited("R" + req.ip, 30, 60 * 60e3)) return res.status(429).json({ erro: "Muitas requisições" });
  const b = req.body || {}, nome = S(b.nome, 80).trim();
  if (!nome) return res.status(400).json({ erro: "Nome obrigatório" });
  const comp = {};
  for (const [k, v] of Object.entries(b.comp || {}).slice(0, 30)) comp[S(k, 60)] = N(v, 0, 100);
  const d = {
    nome, data: new Date().toISOString(), modelo: S(b.modelo, 60),
    pts: N(b.pts, 0, 1e4), max: N(b.max, 0, 1e4), pct: N(b.pct, 0, 100),
    nivel: ["Básico", "Intermediário", "Avançado", "Expert"].includes(b.nivel) ? b.nivel : "Básico",
    cer: N(b.cer, 0, 1e3), err: N(b.err, 0, 1e3), pn: (Array.isArray(b.pn) ? b.pn : []).slice(0, 3).map(x => N(x, 0, 100)),
    comp, desc: N(b.desc, 0, 90), seg: N(b.seg, 0, 1e6),
    int: S(b.int), com: S(b.com), plat: S(b.plat), fmt: S(b.fmt),
    mot: A(b.mot), cont: A(b.cont), comc: A(b.comc), per: A(b.per), hor: A(b.hor)
  };
  await pool.query("INSERT INTO resultados(dados) VALUES($1)", [d]);
  res.json({ ok: true });
});
app.get("/api/admin/resultados", auth, async (_, res) => {
  const r = await pool.query("SELECT id, dados FROM resultados ORDER BY id DESC");
  res.json(r.rows.map(x => ({ id: String(x.id), ...x.dados })));
});
app.delete("/api/admin/resultados/:id", auth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ erro: "ID inválido" });
  await pool.query("DELETE FROM resultados WHERE id=$1", [id]);
  res.json({ ok: true });
});

/* ---- análise (IA opcional; a chave fica só no servidor) ---- */
app.post("/api/analise", async (req, res) => {
  if (limited("I" + req.ip, 20, 60 * 60e3)) return res.status(429).json({ erro: "Muitas requisições" });
  const { nivel = "", pct = 0, pn = [], comp = {} } = req.body || {};
  const ent = Object.entries(comp).map(([k, v]) => [S(k, 60), N(v, 0, 100)]).sort((a, b) => b[1] - a[1]);
  const fortes = ent.slice(0, 2).map(x => x[0]).join(" e "), fracos = ent.slice(-2).map(x => x[0]).join(" e ");
  const base = `Resumo: nível ${S(nivel, 20)} com ${N(pct, 0, 100)}% de aproveitamento.\nPontos fortes: ${fortes || "—"}.\nPontos de atenção: ${fracos || "—"}.\nRecomendação: priorizar esses conteúdos durante o Intensivão.`;
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return res.json({ texto: base });
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || "claude-sonnet-5-5", max_tokens: 600,
        messages: [{ role: "user", content: `Instrutor de Excel: em português, escreva uma análise curta com Resumo, Pontos fortes, Pontos fracos e foco recomendado para o Intensivão. Nível ${S(nivel, 20)}, ${N(pct, 0, 100)}%, por nível ${JSON.stringify(pn)}, competências ${JSON.stringify(Object.fromEntries(ent))}.` }] })
    });
    const j = await r.json();
    res.json({ texto: j.content?.map(c => c.text || "").join("") || base });
  } catch { res.json({ texto: base }); }
});

app.use(express.static("public"));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ erro: "Erro interno" }); });
app.listen(process.env.PORT || 3000, () => console.log("Servidor no ar"));
