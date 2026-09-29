const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Pool de conexão PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Middleware
app.use(cors());
app.use(express.json());

// Aguardar conexão com o banco
async function waitForDB(maxRetries = 10, delayMs = 2000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const result = await pool.query('SELECT 1');
      console.log('Conexão com banco estabelecida');
      return true;
    } catch (err) {
      console.log(`Tentativa ${i + 1}/${maxRetries} de conexão com banco...`);
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
  }
  throw new Error('Não foi possível conectar ao banco após múltiplas tentativas');
}

// Criar tabela users se não existir
async function initDB() {
  try {
    await waitForDB();
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT false,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Tabela users verificada/criada com sucesso');
    
    // Verificar se a tabela foi criada
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'users'
      );
    `);
    console.log('Tabela users existe:', tableExists.rows[0].exists);
    
  } catch (err) {
    console.error('Erro fatal ao inicializar banco:', err.message);
    throw err;
  }
}

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha obrigatórios' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Log de acesso
    await pool.query(
      `INSERT INTO login_logs (user_id, email, success) VALUES ($1, $2, $3)`,
      [user.id, user.email, true]
    );

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        is_admin: user.is_admin,
      },
    });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, senha e nome obrigatórios' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name`,
      [email, hashedPassword, name]
    );

    res.status(201).json({
      success: true,
      user: result.rows[0],
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Email já cadastrado' });
    }
    console.error('Erro no registro:', err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Listar usuários
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, name, is_admin, status FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========== CRUD USUÁRIOS PORTAL ==========

// GET /api/users - Listar todos os usuários
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, is_admin, departments, companies, created_at FROM users_portal ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// POST /api/users - Criar novo usuário
app.post('/api/users', async (req, res) => {
  const { email, password, name, is_admin, departments, companies } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const depsJSON = JSON.stringify(departments || []);
    const compsJSON = JSON.stringify(companies || []);

    const result = await pool.query(
      'INSERT INTO users_portal (email, password_hash, name, is_admin, departments, companies) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, name, is_admin, created_at',
      [email.toLowerCase(), hashedPassword, name, is_admin || false, depsJSON, compsJSON]
    );

    res.status(201).json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Erro ao criar usuário:', err);
    if (err.code === '23505') { // Unique violation
      res.status(409).json({ error: 'Email já cadastrado' });
    } else {
      res.status(500).json({ error: 'Erro ao criar usuário' });
    }
  }
});

// PUT /api/users/:email - Atualizar usuário
app.put('/api/users/:email', async (req, res) => {
  const emailParam = req.params.email.toLowerCase();
  const { password, name, is_admin, departments, companies } = req.body;

  try {
    let query = 'UPDATE users_portal SET updated_at = CURRENT_TIMESTAMP';
    const params = [];
    let paramCount = 1;

    if (name) {
      query += `, name = $${paramCount}`;
      params.push(name);
      paramCount++;
    }
    if (typeof is_admin === 'boolean') {
      query += `, is_admin = $${paramCount}`;
      params.push(is_admin);
      paramCount++;
    }
    if (departments) {
      query += `, departments = $${paramCount}`;
      params.push(JSON.stringify(departments));
      paramCount++;
    }
    if (companies) {
      query += `, companies = $${paramCount}`;
      params.push(JSON.stringify(companies));
      paramCount++;
    }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += `, password_hash = $${paramCount}`;
      params.push(hashedPassword);
      paramCount++;
    }

    query += ` WHERE LOWER(email) = $${paramCount} RETURNING id, email, name, is_admin, created_at`;
    params.push(emailParam);

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// DELETE /api/users/:email - Deletar usuário
app.delete('/api/users/:email', async (req, res) => {
  const emailParam = req.params.email.toLowerCase();

  if (emailParam === 'adm@adm.com.br') {
    return res.status(403).json({ error: 'Não é permitido deletar o usuário admin padrão' });
  }

  try {
    const result = await pool.query(
      'DELETE FROM users_portal WHERE LOWER(email) = $1 RETURNING email',
      [emailParam]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ success: true, message: 'Usuário deletado com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar usuário:', err);
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// Iniciar servidor
initDB()
  .then(() => {
    const server = app.listen(PORT, () => {
      console.log(`API iniciada com sucesso em porta ${PORT}`);
      console.log(`Health check: http://localhost:${PORT}/api/health`);
    });
    
    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('SIGTERM recebido, encerrando gracefully...');
      server.close(() => {
        pool.end(() => process.exit(0));
      });
    });
  })
  .catch((err) => {
    console.error('Falha crítica ao inicializar API:', err.message);
    console.error('Stack:', err.stack);
    process.exit(1);
  });

module.exports = app;
