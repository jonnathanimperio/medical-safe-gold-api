# Medical Safe Gold - Backend API

API backend para o Medical Safe Gold, construida com FastAPI + MongoDB Atlas.

## Requisitos

- Python 3.10 ou superior
- MongoDB Atlas (ou MongoDB local)
- pip

## Instalacao

```bash
# Clone o repositorio
git clone https://github.com/jonnathanimperio/medical-safe-gold-api.git
cd medical-safe-gold-api

# Crie um ambiente virtual
python -m venv venv

# Ative o ambiente virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instale as dependencias
pip install -r requirements.txt
```

## Configuracao

Copie o arquivo `.env.example` para `.env` e preencha com seus valores:

```bash
cp .env.example .env
```

### Variaveis de ambiente obrigatorias

| Variavel     | Descricao                                    |
|-------------|----------------------------------------------|
| `MONGO_URI` | URI de conexao com o MongoDB Atlas           |
| `MASTER_KEY`| Chave mestre Fernet para criptografia        |

### Variaveis opcionais

| Variavel        | Descricao                              | Padrao              |
|----------------|----------------------------------------|---------------------|
| `JWT_SECRET`   | Segredo para tokens JWT                | Auto-gerado         |
| `ADMIN_KEY`    | Chave para endpoints administrativos   | msggold-admin-2024-secret |
| `SMTP_HOST`    | Servidor SMTP                          | smtp.gmail.com      |
| `SMTP_PORT`    | Porta SMTP                             | 587                 |
| `SMTP_USER`    | Usuario SMTP                           | (vazio)             |
| `SMTP_PASSWORD`| Senha SMTP                             | (vazio)             |
| `SMTP_FROM`    | E-mail remetente                       | noreply@medicalsafegold.com |

### Gerar uma MASTER_KEY

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Como rodar

```bash
# Carregue as variaveis de ambiente
# Windows (PowerShell):
$env:MONGO_URI="sua_uri_aqui"
$env:MASTER_KEY="sua_chave_aqui"

# Linux/Mac:
export MONGO_URI="sua_uri_aqui"
export MASTER_KEY="sua_chave_aqui"

# Inicie o servidor
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

O servidor vai iniciar em `http://localhost:8000`.

### Usando arquivo .env (alternativa)

Instale o `python-dotenv` (ja incluido nas dependencias) e crie um arquivo `.env`:

```bash
# Inicie com dotenv
python -c "from dotenv import load_dotenv; load_dotenv()" && uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Deploy (Producao)

### Render.com

1. Conecte seu repositorio GitHub no Render.com
2. Selecione "Web Service"
3. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Adicione as variaveis de ambiente (MONGO_URI, MASTER_KEY)
5. Deploy

### Qualquer VPS (DigitalOcean, Oracle Cloud, AWS, etc.)

```bash
# Clone e instale
git clone https://github.com/jonnathanimperio/medical-safe-gold-api.git
cd medical-safe-gold-api
pip install -r requirements.txt

# Configure as variaveis de ambiente
export MONGO_URI="sua_uri"
export MASTER_KEY="sua_chave"

# Rode com gunicorn (producao)
pip install gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## Endpoints da API

### Autenticacao
- `POST /auth/register` - Cadastro com chave de licenca
- `POST /auth/login` - Login com e-mail e senha
- `POST /auth/forgot-password` - Solicitar codigo de recuperacao
- `POST /auth/reset-password` - Redefinir senha com codigo

### Agendamentos
- `POST /appointments` - Salvar agendamento (criptografado)
- `GET /appointments/{clinica_id}` - Listar agendamentos
- `DELETE /appointments/{appointment_id}?clinica_id=X` - Excluir agendamento

### Assinaturas
- `POST /subscription/activate` - Ativar assinatura
- `GET /subscription/status/{email}` - Verificar status

### Admin
- `POST /admin/license/generate` - Gerar chave de licenca
- `POST /admin/license/batch` - Gerar licencas em lote (CSV)
- `GET /admin/licenses` - Listar todas as licencas
- `DELETE /admin/license/{key}` - Revogar licenca

### Health
- `GET /health` - Status do servidor e banco de dados
- `GET /` - Info basica da API

## Estrutura

```
medical-safe-gold-api/
├── app/
│   └── main.py          # Codigo principal da API (FastAPI)
├── requirements.txt     # Dependencias Python
├── render.yaml          # Configuracao para deploy no Render.com
├── Procfile             # Configuracao para deploy (Heroku/Railway)
├── Dockerfile           # Container Docker
├── .env.example         # Exemplo de variaveis de ambiente
└── README.md
```

## Autor

**Jonnathan Coelho Silva**
