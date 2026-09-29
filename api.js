const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ==================== CORS ====================
// Origens autorizadas a chamar a API pelo navegador (GitHub Pages do portal).
// Origens adicionais podem ser informadas na variavel CORS_ORIGINS, separadas por virgula.
const ALLOWED_ORIGINS = [
  'https://luizmelo8.github.io',
  'https://luizfprof-lgtm.github.io',
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(o => o.trim()) : [])
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json());

// ==================== TOKEN DE SESSAO (HMAC) ====================
// Usa SESSION_SECRET quando definido; caso contrario deriva um segredo da DATABASE_URL.
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update(String(process.env.DATABASE_URL || 'ara-portal')).digest('hex');
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const ADMIN_PRINCIPAL = 'adm@adm.com.br';

function signToken(email) {
  const exp = Date.now() + TOKEN_TTL_MS;
  const payload = Buffer.from(JSON.stringify({ email, exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return { token: `${payload}.${sig}`, exp };
}

function readToken(req) {
  const header = req.headers.authorization || '';
  const raw = header.startsWith('Bearer ') ? header.slice(7) : '';
  const [payload, sig] = raw.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch (e) {
    return null;
  }
}

// Middleware: exige token valido e usuario administrador
async function isAdmin(req, res, next) {
  try {
    const session = readToken(req);
    if (!session) {
      return res.status(401).json({ error: 'Sessão inválida ou expirada' });
    }

    const user = await pool.query(
      'SELECT is_admin FROM users_portal WHERE LOWER(email) = LOWER($1)',
      [session.email]
    );

    if (!user.rows[0]?.is_admin) {
      return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
    }

    req.userEmail = session.email;
    next();
  } catch (err) {
    console.error('Erro ao verificar admin:', err);
    res.status(500).json({ error: 'Erro ao verificar permissões' });
  }
}

function parseList(value) {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function publicUser(row) {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    is_admin: row.is_admin,
    departments: parseList(row.departments),
    companies: parseList(row.companies),
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

// ==================== ENDPOINTS CRUD (ADMIN) ====================

// GET /api/users - Listar todos os usuarios (sem senhas)
app.get('/api/users', isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, is_admin, departments, companies, created_at, updated_at FROM users_portal ORDER BY created_at ASC'
    );
    res.json(result.rows.map(publicUser));
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// GET /api/users/passwords - Listar COM hash de senha (ADMIN)
app.get('/api/users/passwords', isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, is_admin, password_hash, departments, companies, created_at FROM users_portal ORDER BY created_at ASC'
    );

    console.log(`[AUDITORIA] ${req.userEmail} consultou hashes de senha em ${new Date().toISOString()}`);

    res.json(result.rows.map(u => ({
      id: u.id,
      email: u.email,
      name: u.name,
      is_admin: u.is_admin,
      password_hash: u.password_hash,
      departments: parseList(u.departments),
      companies: parseList(u.companies),
      created_at: u.created_at
    })));
  } catch (err) {
    console.error('Erro ao listar senhas:', err);
    res.status(500).json({ error: 'Erro ao listar senhas' });
  }
});

// POST /api/users - Criar novo usuario
app.post('/api/users', isAdmin, async (req, res) => {
  try {
    const { email, password, name, is_admin, departments, companies } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users_portal (email, password_hash, name, is_admin, departments, companies)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, email, name, is_admin, departments, companies, created_at, updated_at`,
      [
        String(email).trim().toLowerCase(),
        hashedPassword,
        name,
        is_admin === true,
        JSON.stringify(departments || []),
        JSON.stringify(companies || [])
      ]
    );

    console.log(`[AUDITORIA] ${req.userEmail} criou o usuário ${email} em ${new Date().toISOString()}`);
    res.status(201).json(publicUser(result.rows[0]));
  } catch (err) {
    console.error('Erro ao criar usuário:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

// PUT /api/users/:email - Atualizar usuario
app.put('/api/users/:email', isAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    const { password, name, is_admin, departments, companies } = req.body;

    if (email.toLowerCase() === ADMIN_PRINCIPAL && is_admin === false) {
      return res.status(403).json({ error: 'Não é possível remover o perfil de administrador principal' });
    }

    const sets = [];
    const values = [];
    let n = 1;

    if (name) { sets.push(`name = $${n++}`); values.push(name); }
    if (password) {
      sets.push(`password_hash = $${n++}`);
      values.push(await bcrypt.hash(password, 10));
    }
    if (is_admin !== undefined) { sets.push(`is_admin = $${n++}`); values.push(is_admin === true); }
    if (departments) { sets.push(`departments = $${n++}`); values.push(JSON.stringify(departments)); }
    if (companies) { sets.push(`companies = $${n++}`); values.push(JSON.stringify(companies)); }
    sets.push('updated_at = NOW()');

    values.push(email);
    const result = await pool.query(
      `UPDATE users_portal SET ${sets.join(', ')} WHERE LOWER(email) = LOWER($${n})`,
      values
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const userResult = await pool.query(
      'SELECT id, email, name, is_admin, departments, companies, created_at, updated_at FROM users_portal WHERE LOWER(email) = LOWER($1)',
      [email]
    );

    console.log(`[AUDITORIA] ${req.userEmail} atualizou o usuário ${email} em ${new Date().toISOString()}`);
    res.json(publicUser(userResult.rows[0]));
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// DELETE /api/users/:email - Excluir usuario (protege adm@adm.com.br)
app.delete('/api/users/:email', isAdmin, async (req, res) => {
  try {
    const { email } = req.params;

    if (email.toLowerCase() === ADMIN_PRINCIPAL) {
      return res.status(403).json({ error: 'Não é possível deletar o usuário administrador principal' });
    }

    const result = await pool.query('DELETE FROM users_portal WHERE LOWER(email) = LOWER($1)', [email]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    console.log(`[AUDITORIA] ${req.userEmail} excluiu o usuário ${email} em ${new Date().toISOString()}`);
    res.json({ message: 'Usuário deletado com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar usuário:', err);
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// ==================== ENDPOINTS DE SENHA (ADMIN) ====================

// PUT /api/users/:email/reset-password
app.put('/api/users/:email/reset-password', isAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    const { new_password } = req.body;

    if (!new_password) {
      return res.status(400).json({ error: 'Nova senha é obrigatória' });
    }

    const hashedPassword = await bcrypt.hash(new_password, 10);

    const result = await pool.query(
      'UPDATE users_portal SET password_hash = $1, updated_at = NOW() WHERE LOWER(email) = LOWER($2) RETURNING email, name',
      [hashedPassword, email]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    console.log(`[AUDITORIA] ${req.userEmail} resetou senha de ${email} em ${new Date().toISOString()}`);
    res.json({ message: 'Senha resetada com sucesso', user: result.rows[0] });
  } catch (err) {
    console.error('Erro ao resetar senha:', err);
    res.status(500).json({ error: 'Erro ao resetar senha' });
  }
});

// GET /api/users/export/passwords - Exporta hashes (ADMIN)
app.get('/api/users/export/passwords', isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT email, name, password_hash FROM users_portal ORDER BY email'
    );

    console.log(`[AUDITORIA] ${req.userEmail} exportou lista de hashes em ${new Date().toISOString()}`);

    res.json({
      exported_at: new Date().toISOString(),
      exported_by: req.userEmail,
      users: result.rows.map(u => ({
        email: u.email,
        name: u.name,
        password_hash: u.password_hash
      }))
    });
  } catch (err) {
    console.error('Erro ao exportar senhas:', err);
    res.status(500).json({ error: 'Erro ao exportar senhas' });
  }
});

// ==================== LOGIN ====================

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    const result = await pool.query('SELECT * FROM users_portal WHERE LOWER(email) = LOWER($1)', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Email ou senha incorretos' });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Email ou senha incorretos' });
    }

    console.log(`[LOGIN] ${email} acessou o portal em ${new Date().toISOString()}`);

    const { token, exp } = signToken(user.email);

    res.json({
      message: 'Login realizado com sucesso',
      token,
      expires_at: exp,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        is_admin: user.is_admin,
        departments: parseList(user.departments),
        companies: parseList(user.companies)
      }
    });
  } catch (err) {
    console.error('Erro ao fazer login:', err);
    res.status(500).json({ error: 'Erro ao fazer login' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'API rodando', timestamp: new Date().toISOString() });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log('Endpoints: POST /api/login | GET/POST /api/users | PUT/DELETE /api/users/:email | GET /api/health');
});

module.exports = app;
