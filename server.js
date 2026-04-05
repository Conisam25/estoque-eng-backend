const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database(path.join(__dirname, "db.sqlite"));
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "troque_esta_chave_em_producao";

app.use(cors());
app.use(express.json());

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'consulta',
  can_register INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  bric TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ativo',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS materials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  setor TEXT NOT NULL,
  quantidade REAL NOT NULL DEFAULT 0,
  minimo REAL NOT NULL DEFAULT 0,
  unidade TEXT NOT NULL DEFAULT 'UN',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS movements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  material_id INTEGER NOT NULL,
  tipo TEXT NOT NULL,
  quantidade REAL NOT NULL,
  projeto_id INTEGER,
  observacao TEXT,
  usuario_id INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
`);

function now() {
  return new Date().toISOString();
}

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

// cria admin se não existir
const admin = db.prepare("SELECT id FROM users WHERE LOWER(username) = ?").get("admin");
if (!admin) {
  const hash = bcrypt.hashSync("9864", 10);
  db.prepare(`
    INSERT INTO users (username, display_name, password_hash, role, can_register, active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run("admin", "Administrador", hash, "admin", 1, 1, now());
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role, can_register: !!user.can_register },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;

  if (!token) return res.status(401).json({ error: "Token ausente" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acesso negado" });
  }
  next();
}

function canRegister(req, res, next) {
  if (!(req.user.role === "admin" || req.user.can_register)) {
    return res.status(403).json({ error: "Sem permissão" });
  }
  next();
}

app.post("/auth/login", (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = req.body?.password || "";

  const user = db.prepare("SELECT * FROM users WHERE LOWER(username)=? AND active=1").get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Login inválido" });
  }

  res.json({
    token: generateToken(user),
    user: {
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      role: user.role,
      can_register: !!user.can_register
    }
  });
});

app.get("/materials", auth, (_req, res) => {
  res.json(db.prepare("SELECT * FROM materials").all());
});

app.post("/materials", auth, canRegister, (req, res) => {
  const { nome, setor, quantidade, unidade } = req.body;

  db.prepare(`
    INSERT INTO materials (nome, setor, quantidade, unidade, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(nome, setor, quantidade, unidade, now(), now());

  res.json({ ok: true });
});

app.delete("/materials/:id", auth, adminOnly, (req, res) => {
  const id = req.params.id;

  db.prepare("DELETE FROM movements WHERE material_id=?").run(id);
  db.prepare("DELETE FROM materials WHERE id=?").run(id);

  res.json({ ok: true });
});

app.post("/movements", auth, canRegister, (req, res) => {
  const { material_id, tipo, quantidade, projeto_id, observacao } = req.body;

  const material = db.prepare("SELECT * FROM materials WHERE id=?").get(material_id);
  if (!material) return res.status(404).json({ error: "Material não encontrado" });

  let estoque = material.quantidade;

  if (tipo === "entrada") estoque += quantidade;
  if (tipo === "saida") estoque -= quantidade;

  db.prepare(`
    INSERT INTO movements (material_id, tipo, quantidade, projeto_id, observacao, usuario_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(material_id, tipo, quantidade, projeto_id, observacao, req.user.id, now());

  db.prepare("UPDATE materials SET quantidade=? WHERE id=?").run(estoque, material_id);

  res.json({ ok: true });
});

// 🔥 AQUI ESTÁ A CORREÇÃO PRINCIPAL
app.get("/movements", auth, (_req, res) => {
  const rows = db.prepare(`
    SELECT
      m.*,
      mt.nome AS material_nome,
      p.nome AS projeto_nome,
      p.bric AS projeto_bric,
      u.display_name AS usuario_nome,
      u.username AS usuario_login
    FROM movements m
    JOIN materials mt ON mt.id = m.material_id
    LEFT JOIN projects p ON p.id = m.projeto_id
    LEFT JOIN users u ON u.id = m.usuario_id
    ORDER BY m.created_at DESC
  `).all();

  res.json(rows);
});

app.listen(PORT, () => {
  console.log("Servidor rodando na porta " + PORT);
});