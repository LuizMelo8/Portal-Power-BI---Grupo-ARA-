const express = require('express');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Middleware para verificar admin
async function isAdmin(req, res, next) {
  try {
    const email = req.headers['x-user-email'];
    if (!email) {
      return res.status(401).json({ error: 'Email do usuário não fornecido' });
    }

    const user = await pool.query(
      'SELECT is_admin FROM users_portal WHERE email = $1',
      [email]
    );

    if (!user.rows[0]?.is_admin) {
      return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
    }

    req.userEmail = email;
    next();
  } catch (err) {
    console.error('Erro ao verificar admin:', err);
    res.status(500).json({ error: 'Erro ao verificar permissões' });
  }
}

// ==================== ENDPOINTS CRUDS ====================

// GET /api/users - Listar todos os usuários (sem senhas)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, is_admin, departments, companies, created_at, updated_at FROM users_portal ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// GET /api/users/passwords - Listar todos COM senhas (ADMIN ONLY)
app.get('/api/users/passwords', isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, is_admin, password_hash, departments, companies, created_at FROM users_portal ORDER BY created_at DESC'
    );
    
    // Log de auditoria
    console.log(`[AUDITORIA] ${req.userEmail} consultou senhas em ${new Date().toISOString()}`);
    
    // Retornar com hash (não vou retornar plaintext por segurança)
    // Se quiser ver plaintext, seria necessário fazer o hash ser reversível, o que não é seguro
    // Vou retornar um endpoint separado que permite RESETAR a senha
    
    res.json(result.rows.map(u => ({
      id: u.id,
      email: u.email,
      name: u.name,
      is_admin: u.is_admin,
      password_hash: u.password_hash, // O hash bcrypt
      departments: u.departments,
      companies: u.companies,
      created_at: u.created_at
    })));
  } catch (err) {
    console.error('Erro ao listar senhas:', err);
    res.status(500).json({ error: 'Erro ao listar senhas' });
  }
});

// POST /api/users - Criar novo usuário
app.post('/api/users', async (req, res) => {
  try {
    const { email, password, name, is_admin, departments, companies } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, senha e nome são obrigatórios' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users_portal (email, password_hash, name, is_admin, departments, companies)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, email, name, is_admin, departments, companies, created_at`,
      [email, hashedPassword, name, is_admin || false, JSON.stringify(departments || []), JSON.stringify(companies || [])]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao criar usuário:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

// PUT /api/users/:email - Atualizar usuário
app.put('/api/users/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const { password, name, is_admin, departments, companies } = req.body;

    let updateQuery = 'UPDATE users_portal SET ';
    const updateValues = [];
    let paramCount = 1;

    if (name) {
      updateQuery += `name = $${paramCount++}, `;
      updateValues.push(name);
    }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateQuery += `password_hash = $${paramCount++}, `;
      updateValues.push(hashedPassword);
    }

    if (is_admin !== undefined) {
      updateQuery += `is_admin = $${paramCount++}, `;
      updateValues.push(is_admin);
    }

    if (departments) {
      updateQuery += `departments = $${paramCount++}, `;
      updateValues.push(JSON.stringify(departments));
    }

    if (companies) {
      updateQuery += `companies = $${paramCount++}, `;
      updateValues.push(JSON.stringify(companies));
    }

    updateQuery += `updated_at = NOW() WHERE email = $${paramCount}`;
    updateValues.push(email);

    const result = await pool.query(updateQuery, updateValues);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Retornar usuário atualizado
    const userResult = await pool.query(
      'SELECT id, email, name, is_admin, departments, companies, created_at, updated_at FROM users_portal WHERE email = $1',
      [email]
    );

    res.json(userResult.rows[0]);
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// DELETE /api/users/:email - Deletar usuário (protege adm@adm.com.br)
app.delete('/api/users/:email', async (req, res) => {
  try {
    const { email } = req.params;

    if (email === 'adm@adm.com.br') {
      return res.status(403).json({ error: 'Não é possível deletar o usuário administrador principal' });
    }

    const result = await pool.query('DELETE FROM users_portal WHERE email = $1', [email]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    res.json({ message: 'Usuário deletado com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar usuário:', err);
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// ==================== ENDPOINTS DE SENHA ====================

// PUT /api/users/:email/reset-password - Reset senha (ADMIN ONLY)
app.put('/api/users/:email/reset-password', isAdmin, async (req, res) => {
  try {
    const { email } = req.params;
    const { new_password } = req.body;

    if (!new_password) {
      return res.status(400).json({ error: 'Nova senha é obrigatória' });
    }

    const hashedPassword = await bcrypt.hash(new_password, 10);

    const result = await pool.query(
      'UPDATE users_portal SET password_hash = $1, updated_at = NOW() WHERE email = $2 RETURNING email, name',
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

// GET /api/users/export/passwords - Export senhas em formato criptografado (ADMIN ONLY) 
app.get('/api/users/export/passwords', isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT email, name, password_hash FROM users_portal ORDER BY email'
    );

    console.log(`[AUDITORIA] ${req.userEmail} exportou lista de senhas em ${new Date().toISOString()}`);

    // Retornar com hash visível (não plaintext, mas o admin vê o hash)
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

    // Log de login
    console.log(`[LOGIN] ${email} acessou o portal em ${new Date().toISOString()}`);

    res.json({
      message: 'Login realizado com sucesso',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        is_admin: user.is_admin,
        departments: typeof user.departments === 'string' ? JSON.parse(user.departments) : user.departments,
        companies: typeof user.companies === 'string' ? JSON.parse(user.companies) : user.companies
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
  console.log(`Endpoints disponíveis:`);
  console.log(`  GET  /api/users`);
  console.log(`  GET  /api/users/passwords (admin only)`);
  console.log(`  POST /api/users`);
  console.log(`  PUT  /api/users/:email`);
  console.log(`  DELETE /api/users/:email`);
  console.log(`  PUT  /api/users/:email/reset-password (admin only)`);
  console.log(`  GET  /api/users/export/passwords (admin only)`);
  console.log(`  POST /api/login`);
  console.log(`  GET  /api/health`);
});

module.exports = app;
