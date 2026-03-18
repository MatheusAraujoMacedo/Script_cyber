# 🛡️ VulnRecon — CLI Security Auditing Tool

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
</p>

Scanner de vulnerabilidades e portas para auditoria de segurança, projetado para rodar diretamente no terminal. Ferramenta leve, rápida e com interface visual estilizada.

---

## 📋 Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| **Port Scanner** | Testa conexões TCP em 20 portas críticas (FTP, SSH, HTTP, MySQL, PostgreSQL, etc.) com threads paralelas |
| **Security Headers** | Analisa a presença de 7 cabeçalhos de segurança HTTP essenciais (HSTS, CSP, X-Frame-Options, etc.) |
| **Directory Fuzzer** | Testa 40+ rotas sensíveis (`.git/`, `.env`, `/admin`, `backup.zip`, etc.) e retorna os status codes |

---

## ⚙️ Configuração do Ambiente

### Pré-requisitos

- **Python 3.8+** instalado na máquina
- **pip** (gerenciador de pacotes do Python)

### Passo a Passo

**1. Clone o repositório ou navegue até a pasta do projeto:**

```bash
cd C:\Users\andso\Desktop\Script_cyber
```

**2. (Recomendado) Crie um ambiente virtual:**

```bash
# Criar o ambiente virtual
python -m venv venv

# Ativar no Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Ativar no Windows (CMD)
.\venv\Scripts\activate.bat

# Ativar no Linux/macOS
source venv/bin/activate
```

**3. Instale as dependências:**

```bash
pip install -r requirements.txt
```

Pronto! O ambiente está configurado. ✅

---

## 🚀 Como Usar

### Uso Básico (executa todos os módulos)

```bash
python vulnrecon.py scanme.nmap.org
```

### Executar Módulos Específicos

```bash
# Apenas o scanner de portas
python vulnrecon.py scanme.nmap.org --ports

# Apenas a análise de cabeçalhos HTTP
python vulnrecon.py scanme.nmap.org --headers

# Apenas o fuzzing de diretórios
python vulnrecon.py scanme.nmap.org --fuzz

# Todos os módulos (explícito)
python vulnrecon.py scanme.nmap.org --all
```

### Opções Avançadas

```bash
# Ajustar o timeout de conexão (padrão: 1.5s)
python vulnrecon.py scanme.nmap.org --all --timeout 3

# Ajustar o número de threads (padrão: 20)
python vulnrecon.py scanme.nmap.org --all --threads 50

# Combinar módulos
python vulnrecon.py scanme.nmap.org -p -H
```

### Atalhos (flags curtas)

| Flag | Módulo |
|------|--------|
| `-p` | Port Scanner |
| `-H` | Security Headers |
| `-f` | Directory Fuzzer |
| `-A` | Todos os módulos |
| `-t` | Timeout (em segundos) |

---

## 📖 Exemplo de Saída

```
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
         R  E  C  O  N

  [✓] Resolved to 45.33.32.156 (scanme.nmap.org)

  ──────────────────────────────────
    ▸ PORT SCANNER
  ──────────────────────────────────
  [OPEN]   80/tcp       HTTP
  [OPEN]   22/tcp       SSH
  [CLOSED] 443/tcp      HTTPS
  [CLOSED] 3306/tcp     MySQL
  ...
```

---

## ⚠️ Aviso Legal

Esta ferramenta é destinada **exclusivamente para fins educacionais e de auditoria autorizada**. Sempre obtenha permissão explícita antes de escanear qualquer alvo.

O domínio `scanme.nmap.org` é disponibilizado pelo projeto Nmap especificamente para testes de scanning autorizados.

> **Nunca utilize esta ferramenta contra sistemas sem autorização prévia.**

---

## 🧰 Tecnologias Utilizadas

- **Python 3** — Linguagem principal
- **socket** — Conexões TCP de baixo nível (port scanning)
- **requests** — Requisições HTTP (headers + fuzzing)
- **concurrent.futures** — Threading para execução paralela
- **argparse** — Parser de argumentos CLI

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
