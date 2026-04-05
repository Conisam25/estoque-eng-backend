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
  created_at TEXT NOT NULL,
  FOREIGN KEY(material_id) REFERENCES materials(id),
  FOREIGN KEY(projeto_id) REFERENCES projects(id),
  FOREIGN KEY(usuario_id) REFERENCES users(id)
);
`);

function now() {
  return new Date().toISOString();
}

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

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

  if (!token) {
    return res.status(401).json({ error: "Token ausente" });
  }

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
    return res.status(403).json({ error: "Sem permissão para cadastrar" });
  }
  next();
}

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "Estoque Eng. backend" });
});

app.post("/auth/login", (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = req.body?.password || "";

  if (!username || !password) {
    return res.status(400).json({ error: "Usuário e senha são obrigatórios" });
  }

  const user = db.prepare("SELECT * FROM users WHERE LOWER(username) = ? AND active = 1").get(username);

  if (!user) {
    return res.status(401).json({ error: "Usuário ou senha inválidos" });
  }

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ error: "Usuário ou senha inválidos" });
  }

  return res.json({
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

app.get("/dashboard", auth, (_req, res) => {
  const totalEstoque = db.prepare("SELECT COALESCE(SUM(quantidade), 0) AS total FROM materials").get().total;
  const baixoEstoque = db.prepare("SELECT COUNT(*) AS total FROM materials WHERE quantidade <= minimo").get().total;
  const obrasAtivas = db.prepare("SELECT COUNT(*) AS total FROM projects WHERE status = 'ativo'").get().total;
  const movimentacoesHoje = db.prepare("SELECT COUNT(*) AS total FROM movements WHERE date(created_at)=date('now')").get().total;

  res.json({ totalEstoque, baixoEstoque, obrasAtivas, movimentacoesHoje });
});

app.get("/materials", auth, (_req, res) => {
  const rows = db.prepare("SELECT * FROM materials ORDER BY nome ASC").all();
  res.json(rows);
});

app.post("/materials", auth, canRegister, (req, res) => {
  const { nome, setor, quantidade, minimo, unidade } = req.body || {};

  if (!nome || !setor || !unidade || quantidade === undefined) {
    return res.status(400).json({ error: "Campos obrigatórios ausentes" });
  }

  const ts = now();

  const result = db.prepare(`
    INSERT INTO materials (nome, setor, quantidade, minimo, unidade, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    String(nome).trim(),
    String(setor).trim(),
    Number(quantidade) || 0,
    Number(minimo) || 0,
    String(unidade).trim(),
    ts,
    ts
  );

  return res.status(201).json({ id: result.lastInsertRowid });
});

app.delete("/materials/:id", auth, adminOnly, (req, res) => {
  const { id } = req.params;

  const material = db.prepare("SELECT * FROM materials WHERE id = ?").get(id);
  if (!material) {
    return res.status(404).json({ error: "Material não encontrado" });
  }

  const tx = db.transaction(() => {
    db.prepare("DELETE FROM movements WHERE material_id = ?").run(id);
    db.prepare("DELETE FROM materials WHERE id = ?").run(id);
  });

  tx();

  return res.json({ ok: true, message: "Material excluído com sucesso" });
});

app.get("/projects", auth, (_req, res) => {
  const rows = db.prepare("SELECT * FROM projects ORDER BY nome ASC").all();
  res.json(rows);
});

app.post("/projects", auth, canRegister, (req, res) => {
  const { nome, bric, status } = req.body || {};

  if (!nome || !bric) {
    return res.status(400).json({ error: "Nome e BRIC são obrigatórios" });
  }

  const result = db.prepare(`
    INSERT INTO projects (nome, bric, status, created_at)
    VALUES (?, ?, ?, ?)
  `).run(
    String(nome).trim(),
    String(bric).trim(),
    status || "ativo",
    now()
  );

  return res.status(201).json({ id: result.lastInsertRowid });
});

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
    LIMIT 100
  `).all();

  res.json(rows);
});

app.post("/movements", auth, canRegister, (req, res) => {
  const { material_id, tipo, quantidade, projeto_id, observacao } = req.body || {};

  if (!material_id || !tipo || quantidade === undefined) {
    return res.status(400).json({ error: "Dados inválidos" });
  }

  const material = db.prepare("SELECT * FROM materials WHERE id = ?").get(material_id);
  if (!material) {
    return res.status(404).json({ error: "Material não encontrado" });
  }

  let novoEstoque = Number(material.quantidade);

  if (tipo === "entrada") {
    novoEstoque += Number(quantidade);
  } else if (tipo === "saida") {
    if (Number(quantidade) > novoEstoque) {
      return res.status(400).json({ error: "Saldo insuficiente" });
    }
    novoEstoque -= Number(quantidade);
  } else if (tipo === "ajuste") {
    novoEstoque = Number(quantidade);
  } else {
    return res.status(400).json({ error: "Tipo de movimento inválido" });
  }

  const tx = db.transaction(() => {
    db.prepare(`
      INSERT INTO movements (material_id, tipo, quantidade, projeto_id, observacao, usuario_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      material_id,
      tipo,
      Number(quantidade),
      projeto_id || null,
      observacao || "",
      req.user.id,
      now()
    );

    db.prepare("UPDATE materials SET quantidade = ?, updated_at = ? WHERE id = ?")
      .run(novoEstoque, now(), material_id);
  });

  tx();

  return res.json({ ok: true, estoque_atual: novoEstoque });
});

app.get("/users", auth, adminOnly, (_req, res) => {
  const rows = db.prepare(`
    SELECT id, username, display_name, role, can_register, active, created_at
    FROM users
    ORDER BY username ASC
  `).all();

  res.json(rows);
});

app.post("/users", auth, adminOnly, (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const display_name = String(req.body?.display_name || "").trim();
  const password = String(req.body?.password || "");
  const role = req.body?.role || "consulta";
  const can_register = !!req.body?.can_register;

  if (!username || !display_name || !password) {
    return res.status(400).json({ error: "Campos obrigatórios ausentes" });
  }

  const exists = db.prepare("SELECT id FROM users WHERE LOWER(username) = ?").get(username);
  if (exists) {
    return res.status(400).json({ error: "Usuário já existe" });
  }

  const hash = bcrypt.hashSync(password, 10);

  db.prepare(`
    INSERT INTO users (username, display_name, password_hash, role, can_register, active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    username,
    display_name,
    hash,
    role,
    can_register ? 1 : 0,
    1,
    now()
  );

  return res.status(201).json({ ok: true });
});

app.delete("/users/:id", auth, adminOnly, (req, res) => {
  const { id } = req.params;

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  if (Number(user.id) === Number(req.user.id)) {
    return res.status(400).json({ error: "O administrador não pode excluir a si mesmo" });
  }

  const hasMovements = db.prepare("SELECT COUNT(*) AS total FROM movements WHERE usuario_id = ?").get(id);

  if (hasMovements.total > 0) {
    return res.status(400).json({
      error: "Este usuário já possui movimentações registradas e não pode ser excluído"
    });
  }

  db.prepare("DELETE FROM users WHERE id = ?").run(id);

  return res.json({ ok: true, message: "Usuário excluído com sucesso" });
});

app.listen(PORT, () => {
  console.log("Servidor rodando na porta " + PORT);
});