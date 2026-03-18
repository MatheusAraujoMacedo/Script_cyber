Markdown
# 🛡️ VulnRecon 3.0 — Enterprise Security Auditing & Recon Tool

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/asyncio-native-success.svg" alt="Asyncio">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
</p>

O **VulnRecon** é um scanner de vulnerabilidades avançado e uma ferramenta de mapeamento de superfície de ataque desenhada para equipas de **Red Team** e pipelines de **DevSecOps**. Construído sobre uma arquitetura puramente assíncrona, oferece varreduras de alta velocidade com capacidades de evasão (Stealth) e relatórios executivos.

---

## 📋 Funcionalidades Core (v3.0)

| Categoria | Funcionalidade | Descrição |
|-----------|----------------|-----------|
| ⚡ **Performance** | **Motor Assíncrono** | I/O não-bloqueante utilizando `aiohttp` e `asyncio` para milhares de requisições simultâneas sem o estrangulamento do GIL. |
| 🥷 **Stealth & Evasão** | **Rotação de Proxies & Jitter** | Evasão de WAFs (Cloudflare, Akamai) através de rotação de IPs e atrasos dinâmicos (`--delay`) entre requisições. |
| 🔐 **Análise DAST** | **Sessões Autenticadas** | Suporte a injeção de Cookies e Bearer Tokens (`--cookie`, `--token`) para auditar painéis internos. |
| ⚙️ **DevSecOps** | **Integração CI/CD** | Retorna `Exit Code 1` ao detetar vulnerabilidades Críticas/Altas, quebrando esteiras no GitHub Actions/GitLab CI. |
| 📊 **Relatórios** | **Exportação Executiva** | Geração automática de relatórios em JSON para máquinas e matrizes de risco em **HTML** para gestão C-Level. |
| 🔎 **Auditoria Web** | **Módulos Aprimorados** | Port Scanner TCP, análise de Security Headers, Deteção de WAF, Fingerprinting de CMS (via `BeautifulSoup`) e Fuzzing de Diretórios com wordlists externas. |

---

## ⚙️ Configuração do Ambiente

### Pré-requisitos
- **Python 3.9+**
- **pip** (gerenciador de pacotes)

### Passo a Passo

**1. Clone o repositório:**
```bash
git clone [https://github.com/seu-usuario/Script_cyber.git](https://github.com/seu-usuario/Script_cyber.git)
cd Script_cyber
2. Crie e ative um ambiente virtual (Recomendado):

Bash
python -m venv venv
# Windows (PowerShell): .\venv\Scripts\Activate.ps1
# Linux/macOS: source venv/bin/activate
3. Instale as dependências assíncronas:

Bash
pip install -r requirements.txt
🚀 Como Usar (Modo Headless / CLI)
O VulnRecon opera num modelo híbrido. Se executado sem argumentos, abre o Menu Interativo (UI no Terminal). Para automação, utilize as flags abaixo:

Reconhecimento Básico
Bash
python vulnrecon.py alvo.com --all
Auditoria DAST (Sessão Autenticada)
Bash
python vulnrecon.py alvo.com --fuzz --cookie "sessionid=xyz123" --token "Bearer abc"
Operações Red Team (Stealth Mode)
Bash
# Usa uma wordlist customizada, rotaciona proxies e aplica um atraso aleatório entre requisições
python vulnrecon.py alvo.com --fuzz --wordlist seclists_admin.txt --proxy-list proxies.txt --delay 1.5
Geração de Relatórios (Para CI/CD e Executivos)
Bash
# Exporta os resultados estruturados no final do scan
python vulnrecon.py alvo.com --all --export report.json --export-html dashboard.html
🔄 Integração DevSecOps (Exemplo GitHub Actions)
O VulnRecon foi desenhado para proteger o seu ciclo de vida de desenvolvimento (SDLC). Exemplo de um passo no seu pipeline.yml:

YAML
- name: Run VulnRecon DAST Scan
  run: |
    python vulnrecon.py staging.alvo.com --all --export report.json
  # O pipeline falhará automaticamente se o VulnRecon retornar exit code 1 (Risco Alto/Crítico)
🧰 Tecnologias Utilizadas
Linguagem: Python 3

Concorrência: asyncio e aiohttp (Substituindo requests e ThreadPoolExecutor)

Parsing de HTML: BeautifulSoup4 (Extração estruturada de DOM)

Argumentos: argparse nativo

UI de Terminal: Códigos de escape ANSI puros e rendering Unicode (Sem dependências pesadas).

⚠️ Aviso Legal e Ética
Esta ferramenta é destinada exclusivamente para fins educacionais, auditorias defensivas (Blue Team) e testes de intrusão autorizados (Red Team).

O uso do VulnRecon contra alvos sem consentimento prévio e mútuo é ilegal. O programador não assume qualquer responsabilidade e não é responsável por qualquer uso indevido ou danos causados por este programa. Para testar com segurança, utilize: scanme.nmap.org.

📄 Licença
Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.


***

### O que mudou e porquê:
1. **O Título e a Descrição:** Foram atualizados para refletir um produto maduro, utilizando palavras-chave como *Enterprise, Red Team, DevSecOps e DAST* em vez de apenas "script de terminal".
2. **A Tabela de Funcionalidades:** Reflete agora a migração para `aiohttp/asyncio`, a capacidade de rodar com sessão iniciada (DAST), as opções de *stealth* e os *exit codes* que quebram pipelines.
3. **Novos Exemplos CLI:** O utilizador que lê o README percebe imediatamente que a ferramenta aceita *proxies*, *wordlists* externas, *cookies* e que gera relatórios em HTML.
4. **Secção DevSecOps:** A inclusão de um exemplo prático em YAML atrai recrutadores da área de
