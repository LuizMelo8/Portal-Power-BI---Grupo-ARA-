# Portal BI Grupo ARA — API Backend

API Node.js/Express para autenticação e gestão de usuários do Portal BI Grupo ARA.

## Endpoints

### POST `/api/login`
Autentica um usuário.

**Request:**
```json
{
  "email": "adm@adm.com.br",
  "password": "ara2026"
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "id": "uuid",
    "email": "adm@adm.com.br",
    "name": "Luiz Melo",
    "is_admin": true
  }
}
```

### POST `/api/register`
Registra um novo usuário.

**Request:**
```json
{
  "email": "user@grupo-ara.com",
  "password": "senha123",
  "name": "Usuário Teste"
}
```

### GET `/api/users`
Lista todos os usuários (sem senhas).

### GET `/api/health`
Health check da API.

## Setup Local

```bash
npm install
cp .env.example .env
# Editar .env com dados do PostgreSQL
npm start
```

## Deploy em Railway

1. Conectar repositório GitHub
2. Railway detecta automaticamente Procfile e package.json
3. Criar variável de ambiente `DATABASE_URL` em Railway
4. Deploy automático

## Variáveis de Ambiente

- `PORT` — porta (padrão: 3000)
- `NODE_ENV` — environment (production/development)
- `DATABASE_URL` — string de conexão PostgreSQL

## Usuários Iniciais

Após deploy, inserir usuários via SQL:

```sql
INSERT INTO users (email, password_hash, name, is_admin, status) 
VALUES 
('adm@adm.com.br', 'HASH_BCRYPT_ARA2026', 'Luiz Melo', true, 'active')
ON CONFLICT (email) DO UPDATE SET updated_at = NOW();
```

**Nota:** As senhas são armazenadas com hash bcrypt. Não use senhas em plain text.

## Arquitetura

- **Express.js** — framework web
- **PostgreSQL** — banco de dados
- **bcryptjs** — hash de senhas
- **CORS** — requisições cross-origin

---

Desenvolvido por Luiz Melo para Grupo ARA.
