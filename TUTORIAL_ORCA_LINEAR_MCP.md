# 📘 Guia Definitivo: Orca + Linear + GitHub via MCP & Agente Antigravity

> **Manual de Configuração, Arquitetura e Guia Prático de Operação no Dia a Dia**  
> *Destinado a equipes de engenharia, líderes técnicos e desenvolvedores que buscam orquestrar agentes de IA com isolamento de tarefas.*

---

## 📌 Sumário Executivo
1. [Visão Geral da Arquitetura](#1-visão-geral-da-arquitetura)
2. [Instalação e Login nos Serviços](#2-instalação-e-login-nos-serviços)
   - [2.1 Orca (Agent Development Environment)](#21-orca-agent-development-environment)
   - [2.2 Linear](#22-linear)
   - [2.3 GitHub](#23-github)
3. [Integração Nativa no Orca (Task Sources)](#3-integração-nativa-no-orca-task-sources)
4. [Configuração do MCP (Model Context Protocol)](#4-configuração-do-mcp-model-context-protocol)
   - [4.1 O que é o MCP e por que usá-lo com agentes](#41-o-que-é-o-mcp-e-por-que-usá-lo-com-agentes)
   - [4.2 Configurando o Linear MCP Server](#42-configurando-o-linear-mcp-server)
   - [4.3 Configurando o GitHub MCP Server](#43-configurando-o-github-mcp-server)
   - [4.4 O arquivo `.mcp.json` unificado](#44-o-arquivo-mcpjson-unificado)
5. [Conectando com o Agente de IA (Antigravity & Outros)](#5-conectando-com-o-agente-de-ia-antigravity--outros)
6. [Guia de Operação Diária: Os Superpoderes do Orca](#6-guia-de-operação-diária-os-superpoderes-do-orca)
   - [Git Worktrees Paralelos](#61-git-worktrees-isolados)
   - [Terminais Persistentes](#62-terminais-persistentes-e-split)
   - [Design Mode & Captura Visual](#63-design-mode-inspeção-visual)
   - [Revisão e Anotação de Diffs](#64-anotação-e-revisão-de-diffs-de-ia)
   - [Fluxo Completo de Entrega (Do Ticket ao PR)](#65-fluxo-completo-ponta-a-ponta)
7. [Metodologia Ágil com Linear: Uso Prático, Regras, PRD & Cycles](#7-metodologia-ágil-com-linear-uso-prático-regras-prd--cycles)
8. [Troubleshooting & Dúvidas Frequentes](#8-troubleshooting--dúvidas-frequentes)

---

## 1. Visão Geral da Arquitetura

O ecossistema moderno de desenvolvimento com agentes de IA integra quatro pilares essenciais:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ORCA (ADE Orchestrator)                         │
│  ┌──────────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │
│  │  Kanban / Task View  │  │  Terminais WebGL  │  │   Diff Viewer   │  │
│  │   (Linear / GitHub)  │  │   (Worktrees)     │  │   & Preview     │  │
│  └──────────┬───────────┘  └─────────┬─────────┘  └────────┬────────┘  │
└─────────────┼────────────────────────┼─────────────────────┼───────────┘
              │                        │                     │
    [Auth Nativa UI]             [Execução CLI]        [Git Commits]
              │                        │                     │
              ▼                        ▼                     ▼
      ┌───────────────┐     ┌─────────────────────┐   ┌─────────────┐
      │  LINEAR APP   │     │ AGENTE ANTIGRAVITY  │   │ GITHUB REPO │
      │  (Gestão)     │     │  (Raciocínio & CLI) │   │  (Código)   │
      └───────┬───────┘     └──────────┬──────────┘   └──────┬──────┘
              │                        │                     │
              │             ┌──────────┴──────────┐          │
              └────────────►│     CAMADA MCP      │◄─────────┘
                            │ (Linear & GitHub    │
                            │  Tools / Resources) │
                            └─────────────────────┘
```

- **Orca (`stablyai/orca`)**: O "Cockpit" ou ADE (Agent Development Environment). Orquestra múltiplos agentes trabalhando em paralelo em **Git Worktrees** separados, evitando conflitos de código e permitindo preview ao vivo.
- **Linear**: Sistema de gerenciamento ágil de tarefas onde são criadas histórias, bugs e especificações.
- **GitHub**: Repositório de código onde branches são criadas, commits são salvos e Pull Requests são abertos.
- **MCP (Model Context Protocol)**: Padrão aberto criado para permitir que modelos de IA executem ferramentas e leiam dados estruturados (consultar issues, comentar tarefas, ler PRs, criar branches) diretamente durante o raciocínio.
- **Antigravity (`agy`)**: O agente de engenharia autônomo que recebe a tarefa, usa os servidores MCP para se contextualizar e codifica a solução no terminal isolado do Orca.

---

## 2. Instalação e Login nos Serviços

### 2.1 Orca (Agent Development Environment)

O Orca está disponível para Windows, macOS e Linux.

#### Instalação no Windows:
1. Acesse o repositório oficial no GitHub: [github.com/stablyai/orca](https://github.com/stablyai/orca) ou o site oficial [stably.ai](https://www.stably.ai).
2. Na aba **Releases**, baixe o instalador `.exe` mais recente (ex: `Orca-Setup-x.x.x.exe`).
3. Execute o instalador e conclua o assistente.
4. Ao abrir pela primeira vez, faça login ou registre sua conta do Stably AI (ou utilize modo local, dependendo da versão).

#### Instalação no macOS:
```bash
brew install --cask stablyai/orca/orca
```

#### Instalação no Linux (Arch/Outros):
```bash
# Arch Linux (AUR)
yay -S stably-orca-bin
```

---

### 2.2 Linear

1. Acesse [linear.app](https://linear.app) e crie uma conta (usando Google, GitHub ou e-mail).
2. Crie ou acesse seu **Workspace** (ex: `meu-time-eng`).
3. Crie um time (Team), por exemplo: **ENG** ou **CORE**.
4. **Gerando a Personal API Key (Necessária para MCP e Orca):**
   - No canto superior esquerdo, clique no seu perfil / nome do Workspace.
   - Acesse **Settings** (Configurações).
   - Na barra lateral sob a seção *Account*, clique em **Security & Access** (Segurança e Acesso).
   - Role até a seção **Personal API Keys**.
   - Clique em **Create Key** (ou `New API Key`).
   - Dê um rótulo claro: `Orca-MCP-Agent`.
   - Copie o token gerado (começa tipicamente com `lin_api_...`). **Guarde-o com segurança!**

---

### 2.3 GitHub

1. Acesse [github.com](https://github.com) e faça login.
2. **Gerando o Personal Access Token (PAT):**
   - Clique na sua foto de perfil no topo direito -> **Settings**.
   - No menu lateral esquerdo, role até o final e clique em **Developer Settings**.
   - Selecione **Personal access tokens** -> **Tokens (classic)** (ou Fine-grained se a organização exigir).
   - Clique em **Generate new token (classic)**.
   - Defina o nome: `Orca-Agent-Integration`.
   - Selecione os seguintes escopos obrigatórios:
     - `repo` (Acesso completo a repositórios privados e públicos).
     - `workflow` (Se o agente for disparar ou ler GitHub Actions).
     - `read:org` (Para listar repositórios de organizações).
   - Clique em **Generate token** e guarde o token (inicia com `ghp_...`).

---

## 3. Integração Nativa no Orca (Task Sources)

O Orca possui uma interface nativa para visualizar seus cards do Linear e repositórios do GitHub lado a lado com os terminais.

### Passo 1: Habilitar as Fontes de Tarefas (Task Sources)
1. No Orca, clique no ícone de engrenagem (**Settings**) no canto inferior esquerdo.
2. Vá em **Task Sources**.
3. Ative os seletores (toggle switches):
   - `Linear` -> **ON**
   - `GitHub` -> **ON**
4. Isso fará com que as abas de tarefas apareçam na barra lateral do Orca.

### Passo 2: Configurar Credenciais em Integrations
1. Ainda dentro de **Settings**, clique na seção **Integrations**.
2. **Conexão com o Linear:**
   - Clique em **Linear**.
   - Escolha o método de autenticação: **OAuth** (clique no botão para autorizar no navegador) ou **Personal API Key** (cole a chave `lin_api_...` gerada no passo anterior).
   - Selecione o Time padrão (ex: `ENG`).
3. **Conexão com o GitHub:**
   - Clique em **GitHub**.
   - Conecte via OAuth ou insira o Personal Access Token (`ghp_...`).
   - Escolha a organização ou conta pessoal padrão.
4. Salve as alterações.

> **Resultado:** Ao voltar para o painel principal do Orca, a aba **Tasks** listará todas as issues ativas do seu Linear e as Pull Requests abertas no GitHub!

---

## 4. Configuração do MCP (Model Context Protocol)

### 4.1 O que é o MCP e por que usá-lo com agentes?

| Integração Nativa do Orca | Servidores MCP (Model Context Protocol) |
|---|---|
| Feita para o **usuário humano** ver cards, listas e PRs na tela. | Feita para a **IA** consultar, raciocinar, ler detalhes técnicos e executar ações via código. |
| Exibe a interface do Kanban. | Permite que o agente execute: `linear_search_issues`, `github_create_pull_request`, etc. |

O MCP padroniza como qualquer agente descobre e chama ferramentas através de chamadas JSON-RPC via `stdio` ou `http`.

---

### 4.2 Configurando o Linear MCP Server

O servidor MCP do Linear é disponibilizado via Node.js/NPX:
- **Pacote**: `@modelcontextprotocol/server-linear` (ou compatíveis como `mcp-server-linear`).
- **Comando de execução**: `npx -y @modelcontextprotocol/server-linear`
- **Variável de Ambiente necessária**: `LINEAR_API_KEY`

---

### 4.3 Configurando o GitHub MCP Server

O servidor oficial MCP do GitHub permite busca de código, commits, issues e PRs:
- **Pacote**: `@modelcontextprotocol/server-github`
- **Comando de execução**: `npx -y @modelcontextprotocol/server-github`
- **Variável de Ambiente necessária**: `GITHUB_PERSONAL_ACCESS_TOKEN`

---

### 4.4 O arquivo `.mcp.json` unificado

No seu repositório de projeto (ou na raiz onde o Orca gerencia suas workspaces), crie um arquivo chamado `.mcp.json`:

```json
{
  "mcpServers": {
    "linear": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-linear"],
      "env": {
        "LINEAR_API_KEY": "lin_api_SEU_TOKEN_DO_LINEAR_AQUI"
      }
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_SEU_TOKEN_DO_GITHUB_AQUI"
      }
    }
  }
}
```

> 🔒 **Dica de Segurança:** Adicione `.mcp.json` ao seu `.gitignore` caso utilize tokens diretos no arquivo, ou configure as variáveis de ambiente no seu sistema operacional (`export LINEAR_API_KEY=...` / `$env:LINEAR_API_KEY=...`).

### Inspecionando o MCP dentro do Orca
1. No Orca, vá em **Settings** -> **Repository** -> **MCP Configs**.
2. O Orca detectará automaticamente o arquivo `.mcp.json` (ou configurações em `.cursor/mcp.json` e `.claude.json`).
3. Você verá o status de cada servidor com indicador verde (**Running / Connected**) e a lista de ferramentas disponíveis prontas para uso pelos agentes.

---

## 5. Configuração Universal de IA Generativa & Agentes no Orca

O Orca foi arquitetado para ser **completamente agnóstico a modelos e agentes**. O **Google Antigravity (`agy`)** é apenas um exemplo de motor; o mesmo processo de orquestração funciona para qualquer agente de codificação moderno, seja baseado em linha de comando (CLI) ou conectado diretamente via API de provedores.

---

### 5.1 O Ecossistema de Agentes Compatíveis

Você pode configurar o Orca para disparar qualquer uma das seguintes opções dentro dos Git Worktrees:

| Agente / Motor | Tipo | Como Instalar no Sistema | Comando no Terminal do Orca |
|---|---|---|---|
| **Google Antigravity** | CLI Autônomo | Binário via `agy install` ou script | `agy` ou `agy "sua instrução"` |
| **Claude Code (Anthropic)** | CLI Autônomo | `npm install -g @anthropic-ai/claude-code` | `claude` |
| **Cursor CLI** | CLI / Headless | Integrado ao Cursor (`cursor-agent`) | `cursor-agent` |
| **Aider** | CLI Pair Programming | `pip install aider-chat` ou `uv tool install aider-chat` | `aider` |
| **OpenCode / Codex** | CLI Open Source | `npm install -g opencode-ai` | `opencode` |
| **Modelos Locais (Ollama/vLLM)** | Endpoint Local | `ollama run qwen2.5-coder` ou `vLLM` | `aider --model ollama/qwen2.5-coder` |

---

### 5.2 Como o Orca Executa e Configura os Agentes

O Orca gerencia a IA através de duas camadas complementares:

#### Camada 1: Configuração do Agente Runner (Settings ➔ Agents & Providers)
1. No Orca, acesse **Settings (engrenagem)** ➔ **Agents & Runners**.
2. **Command / Executable:** Defina o comando base ou o executável do seu agente (ex: `claude`, `agy`, `aider`).
3. **Default Arguments:** Argumentos padrão de inicialização (ex: `--dangerously-skip-permissions` para Claude Code, ou flags de modelo).
4. **Environment Variables:** Injeta chaves de API globais diretamente no ambiente de execução do terminal:
   - `ANTHROPIC_API_KEY`: para Claude Code / modelos Claude.
   - `OPENAI_API_KEY`: para GPT-4o / Codex / Aider.
   - `GEMINI_API_KEY`: para Antigravity / Gemini 2.5 / 3.0.

#### Camada 2: Execução no Git Worktree da Tarefa
Ao clicar com o botão direito em uma issue do Linear e selecionar **"Create Worktree from Task"**:
1. O Orca clona a branch para uma pasta isolada (ex: `.worktrees/LIN-104`).
2. Abre uma instância do terminal WebGL já posicionada dentro dessa pasta.
3. Carrega automaticamente o arquivo `.mcp.json` do projeto, disponibilizando as ferramentas do Linear e GitHub para qualquer agente que você rodar.

---

### 5.3 Diagnóstico Aprofundado: Erros Mais Comuns e Como Resolver

Na prática, a maior parte dos problemas ao integrar IA no Orca não vem da inteligência do modelo, mas de **inconsistências de ambiente do sistema operacional**. Abaixo estão os erros mais frequentes e suas soluções:

---

#### 🔴 Erro 1: "Command not found" / "Não foi possível encontrar a instalação" / "O termo não é reconhecido"

##### Por que acontece?
Aplicativos desktop com interface gráfica (como o Orca, VS Code ou Slack) são iniciados pelo gerenciador de janelas do sistema operacional (Explorer no Windows, Finder no macOS). Por padrão, eles **NÃO herdam o perfil completo do seu terminal interativo** (`.bashrc`, `.zshrc`, ou atualizações recentes de variáveis de ambiente do PowerShell feitas sem reiniciar o computador). 

Se você acabou de instalar o agente via `npm install -g` ou `pip install`, o binário reside em pastas como `AppData\Roaming\npm` ou `~/.local/bin`, mas o terminal do Orca tenta invocar o nome simples e não o encontra no seu `PATH` reduzido.

##### Como Diagnosticar:
Abra o terminal integrado do Orca e execute o comando de localização de binário:
- **No Windows:**
  ```powershell
  where claude
  where agy
  where aider
  ```
- **No macOS / Linux:**
  ```bash
  which claude
  which agy
  which aider
  ```
Se o comando retornar vazio ou *"Não foi possível encontrar o arquivo"*, o binário está fora do `PATH` visível pelo Orca.

##### Como Resolver (3 Soluções Práticas):

* **Solução A (Mais Confiável): Configurar o Caminho Absoluto no Orca**  
  Em vez de colocar apenas `claude` ou `agy` nas configurações do Orca, use o caminho físico completo do arquivo executável:
  - **Windows (npm global):**  
    `C:\Users\SEU_USUARIO\AppData\Roaming\npm\claude.cmd`
  - **Windows (Python/pip global):**  
    `C:\Users\SEU_USUARIO\AppData\Local\Programs\Python\Python313\Scripts\aider.exe`
  - **Windows (Antigravity CLI):**  
    `C:\Users\SEU_USUARIO\.gemini\antigravity-cli\bin\agentapi.bat`
  - **macOS / Linux:**  
    `/usr/local/bin/claude` ou `/Users/SEU_USUARIO/.nvm/versions/node/v20.x/bin/claude`

* **Solução B: Injetar o PATH nas Configurações do Orca**  
  Vá em **Settings ➔ Environment** dentro do Orca e adicione a pasta de binários global:
  - Windows: Adicione `;C:\Users\SEU_USUARIO\AppData\Roaming\npm` ao final da variável `PATH`.
  - macOS/Linux: Adicione `:/usr/local/bin:~/.nvm/versions/node/v20.0.0/bin` ao `PATH`.

* **Solução C: Reiniciar o Orca após instalações globais**  
  Se você instalou uma ferramenta no terminal externo enquanto o Orca estava aberto, feche totalmente o Orca (inclusive na bandeja do sistema) e reabra-o para recarregar as variáveis de ambiente.

---

#### 🔴 Erro 2: "Script desabilitado / Execution Policy" (Exclusivo do Windows)

##### Sintoma:
Ao tentar rodar um agente instalado via npm (ex: `claude` ou `opencode`), o terminal do Orca exibe:
```
claude.ps1 não pode ser carregado porque a execução de scripts foi desabilitada neste sistema.
+ CategoryInfo : SecurityError: (:) [], PSSecurityException
```

##### Como Resolver:
Abra o PowerShell no seu computador como **Administrador** e execute:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Isso autoriza a execução de scripts e wrappers de linha de comando legítimos instalados na sua conta de usuário.

---

#### 🔴 Erro 3: "API Key Missing" / Chave de API não detectada pelo Agente

##### Sintoma:
O agente abre no terminal, mas fecha imediatamente exibindo:
`Error: No API key found. Please set ANTHROPIC_API_KEY / OPENAI_API_KEY`.

##### Como Resolver:
1. **Configuração Global no Orca:** Em **Settings ➔ Agents & Providers**, preencha o campo respectivo à chave da IA.
2. **Configuração via Arquivo `.env`:** No repositório ou no worktree, crie um arquivo `.env` (certifique-se de que está listado no `.gitignore`):
   ```env
   ANTHROPIC_API_KEY=sk-ant-api03-...
   OPENAI_API_KEY=sk-proj-...
   GEMINI_API_KEY=AIzaSy...
   ```
3. **Teste no Terminal do Orca:** Antes de rodar o agente, verifique se a variável está carregada:
   - Windows PowerShell: `$env:ANTHROPIC_API_KEY`
   - macOS / Linux: `echo $ANTHROPIC_API_KEY`

---

#### 🔴 Erro 4: Agente Congelado Aguardando Confirmação Interativa

##### Sintoma:
Ao mandar o agente resolver uma tarefa do Linear, o processo parece congelar sem responder.

##### Causa:
Agentes de IA costumam solicitar aprovação manual humana antes de rodar comandos no sistema (ex: `Allow bash command 'git checkout -b'? [y/n]`).

##### Como Resolver:
Ao configurar o comando padrão do agente no Orca, adicione a flag de execução autônoma segura:
- **Claude Code:** `claude --dangerously-skip-permissions` (ou configurar permissões automáticas no arquivo `~/.claude.json`).
- **Aider:** `aider --yes --auto-commits`
- **Antigravity (`agy`):** `agy --auto-approve` ou execução com o prompt parametrizado.

---

#### 🔴 Erro 5: Incompatibilidade de Versão do Node.js ou Python

##### Sintoma:
Erros como `SyntaxError: Unexpected token '?'` ou `Requires Node >= 18.0.0`.

##### Como Resolver:
1. No terminal do Orca, confira a versão do runtime:
   ```bash
   node -v
   python --version
   ```
2. Caso esteja usando versões legadas, utilize gerenciadores de versão como `nvm` (para Node) ou `uv` / `pyenv` (para Python) para definir a versão estável mais recente como padrão global do sistema.

---

---

## 6. Guia de Operação Diária: Os Superpoderes do Orca

O Orca foi desenhado para maximizar a velocidade de desenvolvimento com agentes autônomos. Aqui estão os 5 recursos mais usados no dia a dia:

### 6.1 Git Worktrees Isolados (Adeus conflitos de branch)
- **O Problema Antigo:** Ao rodar uma IA no seu repositório local, ela altera arquivos na branch atual. Se você quiser rodar outra IA para outro bug, seus arquivos ficam misturados.
- **A Solução do Orca:** Cada tarefa cria um **Worktree**. São pastas físicas separadas que compartilham o mesmo histórico `.git`.
- **Na Prática:** Você pode colocar 3 agentes trabalhando ao mesmo tempo:
  - Agente 1 no Worktree `LIN-101` (refatorando backend).
  - Agente 2 no Worktree `LIN-102` (criando página de login).
  - Agente 3 no Worktree `LIN-103` (corrigindo bug de CSS).
- Você compara os resultados e faz o merge apenas do que ficou perfeito.

### 6.2 Terminais Persistentes e Split
- Terminais de alta performance baseados em WebGL (Ghostty-class).
- O histórico e as sessões continuam rodando mesmo se você fechar a janela ou reiniciar o aplicativo.
- Suporte a divisões horizontais e verticais infinitas: acompanhe o log do servidor backend de um lado e o agente codificando do outro.

### 6.3 Design Mode (Inspeção Visual Web)
- Se seu projeto tem frontend web, o Orca possui um navegador Chromium integrado.
- Ao ativar o **Design Mode**, você clica com o mouse em qualquer elemento visual da tela (um botão desalinhado, um modal quebrado).
- O Orca captura automaticamente:
  - O HTML do componente.
  - O CSS computado.
  - Um screenshot recortado do elemento.
  - Injeta tudo diretamente no prompt do agente com um clique!

### 6.4 Anotação e Revisão de Diffs de IA
- Quando o agente finaliza o código, o Orca abre um visualizador de diff (estilo GitHub PR).
- Em vez de aceitar o código cegamente, você pode selecionar linhas e adicionar comentários:
  - *"Altere essa função para usar async/await em vez de Promise puro."*
- Clique em **Send to Agent**: o Orca reenvia as anotações para o agente refazer apenas aquele trecho.

### 6.5 Fluxo Completo Ponta a Ponta (Cheat Sheet Diário)

| Etapa | Ação no Orca | O que o Agente Faz |
|---|---|---|
| **1. Seleção** | Clicar na issue `LIN-123` no painel do Linear | Cria Git Worktree `feature/LIN-123` |
| **2. Prompt** | Digitar a instrução ou disparar o agente | Agente lê a issue via MCP Linear |
| **3. Execução** | Monitorar o terminal do Orca | Agente cria código, roda linters e testes |
| **4. Visual** | Abrir preview web e inspecionar no Design Mode | Ajusta CSS/layout conforme necessário |
| **5. Review** | Revisar o Diff no painel do Orca e comentar | Agente refina os detalhes apontados |
| **6. Ship** | Clicar em "Create Pull Request" | Agente abre PR no GitHub e atualiza Linear |

---

## 7. Metodologia Ágil com Linear: Uso Prático, Regras, PRD & Cycles

Para que a automação com agentes de IA (como Antigravity) e o Orca funcione com máxima eficiência, o **Linear não pode ser usado como um bloco de notas desorganizado**. Ele é o **cérebro de dados estruturados** que orienta tanto engenheiros humanos quanto agentes autônomos.

---

### 7.1 O Uso Prático do Linear no Fluxo de Engenharia

O Linear foi projetado com a filosofia *keyboard-first* (orientado a atalhos rápidos), eliminando a burocracia pesada de ferramentas legadas (como Jira). No dia a dia da equipe:

1. **Central Única da Verdade:** Nenhum trabalho de código começa sem um ticket existente no Linear.
2. **Ciclo de Vida Integrado com Git e Orca:**
   - `Backlog` ➔ Ideias, sugestões e débitos técnicos ainda não priorizados.
   - `Triage` ➔ Novas issues criadas (ex: bugs reportados por clientes) aguardando validação do Tech Lead.
   - `Todo / Ready` ➔ Tarefa planejada para o ciclo atual, pronta e cumprindo a *Definition of Ready (DoR)*.
   - `In Progress` ➔ O desenvolvedor ou o Orca criou o Git Worktree associado à tarefa (`feature/LIN-101`).
   - `In Review` ➔ O Pull Request no GitHub foi aberto (o agente via MCP atualiza o estado automaticamente).
   - `Done` ➔ O PR foi mergeado na branch `main` e a issue é fechada automaticamente pelo webhook do GitHub.
   - `Canceled` ➔ Tarefa descartada com comentário explicativo obrigatório do motivo.

---

### 7.2 Regras Mandatórias ao Subir Tarefas (Definition of Ready - DoR)

> ⚠️ **Regra de Ouro para Agentes de IA:**  
> Se a tarefa for ambígua para um engenheiro humano, ela gerará **alucinações ou código incorreto** em alta velocidade se passada para um Agente de IA. A qualidade do output do agente é 100% proporcional à clareza do ticket no Linear!

#### Regra 1: Nomenclatura Padronizada de Títulos
O título deve seguir rigorosamente a taxonomia:
`[Módulo/Domínio] Verbo no imperativo + Objeto + Contexto resumido`

- ✅ **Exemplos Corretos:**
  - `[Auth/JWT] Implementar renovação automática de refresh token no endpoint /auth/refresh`
  - `[Checkout/Stripe] Corrigir cálculo de frete para compras internacionais acima de 2kg`
  - `[DB/Migration] Criar índice na coluna user_id da tabela audit_logs`
- ❌ **Exemplos Inaceitáveis:**
  - `Bug no login`
  - `Arrumar front`
  - `Melhorar performance`

#### Regra 2: Estrutura Obrigatória da Descrição (Template de Issue)
Toda tarefa criada deve conter as 4 seções abaixo:

```markdown
### 1. Contexto & Problema
Qual comportamento atual está quebrado ou qual necessidade do usuário precisa ser atendida.

### 2. Escopo Técnico & Arquitetura
- O que DEVE ser alterado (ex: serviços, endpoints, tabelas).
- O que NÃO deve ser alterado (fronteiras do que está fora de escopo para evitar refatorações indesejadas pelo agente).

### 3. Critérios de Aceitação (Definition of Done)
- [ ] O endpoint `/auth/refresh` retorna status 200 e novo access_token quando enviado refresh_token válido.
- [ ] Retorna status 401 caso o refresh_token esteja expirado ou revogado.
- [ ] Cobertura de testes unitários adicionada para os cenários de sucesso e falha.

### 4. Anexos & Referências
- Link do PRD ou documento de arquitetura no Linear Documents.
- Link do Figma / Mockup (se envolver frontend).
- Logs de erro ou cURL para reprodução (se for bug).
```

#### Regra 3: Metadados e Classificação Obrigatórios
Nenhuma tarefa deve ir para `Todo` sem os seguintes campos preenchidos:
- **Priority:**
  - `Urgent` (P1) ➔ Bloqueia produção ou clientes pagantes. Resolução imediata.
  - `High` (P2) ➔ Funcionalidade essencial do ciclo atual.
  - `Medium` (P3) ➔ Melhoria ou bug não impeditivo.
  - `Low` (P4) ➔ Débito cosmético ou oportunidade futura.
- **Estimate (Estimativa):** Pontuação em Fibonacci (`1, 2, 3, 5, 8`). Tarefas com `8+` devem ser fatiadas em sub-tarefas menores.
- **Project:** Toda tarefa de funcionalidade deve pertencer a um Projeto/Épico.
- **Labels:** Tags funcionais como `frontend`, `backend`, `bug`, `feature`, `mcp-ready`.

---

### 7.3 A Importância Central do PRD (Product Requirements Document)

Na era do desenvolvimento com IA, o PRD **deixou de ser burocracia** e virou o **mapa estratégico de contexto**:

1. **A IA é um Desenvolvedor Júnior com Velocidade Sênior:**  
   Um modelo de IA executa exatamente o que lê. Se ele só ler uma issue atômica, pode tomar decisões de design que quebram o restante da plataforma.
2. **O PRD como Âncora de Contexto via MCP:**  
   No Linear, os PRDs são escritos nativamente no recurso **Linear Documents** e vinculados diretamente ao Projeto. Quando o agente Antigravity consulta o projeto via MCP (`linear_get_project`), ele tem acesso à visão holística do produto:
   - Casos de borda (Edge cases).
   - Regras de negócio restritas.
   - Decisões arquiteturais já tomadas (ex: *"usar PostgreSQL com Drizzle ORM, não Prisma"*).
3. **Estrutura Mínima de um PRD Ágil (1 a 2 páginas):**
   - **Problema & Valor:** Por que estamos construindo isso e qual métrica queremos mover?
   - **Personas & Casos de Uso:** Quem usa e qual o fluxo ideal da jornada?
   - **Escopo (In-Scope vs. Out-of-Scope):** Delimitação explícita do que NÃO será feito nesta versão.
   - **Requisitos Funcionais & Não-Funcionais:** Regras de negócio, SLAs de performance e requisitos de segurança.
   - **Modelagem de Dados e Contratos de API:** DTOs esperados, schemas e payloads.

---

### 7.4 Métodos de Criação e Gestão de Sprints no Linear (Cycles)

Diferente das cerimônias burocráticas do Scrum tradicional, o Linear gerencia sprints através de **Cycles (Ciclos Contínuos)**.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CICLO DO LINEAR (2 SEMANAS)                     │
│                                                                        │
│   [Segunda - Início]              [Execução Contínua]       [Sexta]    │
│   ┌────────────────┐              ┌─────────────────┐       ┌────────┐ │
│   │ Planning       │ ───────────► │ Orca + Worktree │ ────► │ Review │ │
│   │ Seleção Todo   │              │ + Agente MCP    │       │ & Ship │ │
│   └────────────────┘              └─────────────────┘       └────────┘ │
│           ▲                                                      │     │
│           │               [Auto-Rollover de Não Concluídos]      │     │
│           └──────────────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────────────────────┘
```

#### 1. Configuração Recomendada de Cycles
- **Cadência Padrão:** **2 semanas** (começando sempre às segundas-feiras e terminando na sexta-feira da semana seguinte).
- **Ativação de Automações no Linear:**
  - `Auto-close`: Issues vinculadas a PRs fechados no GitHub mudam para `Done`.
  - `Auto-archive`: Issues finalizadas há mais de 30 dias são arquivadas para manter a visão limpa.
  - `Auto-rollover`: Tarefas que não foram finalizadas até o término do ciclo são automaticamente movidas para o próximo ciclo com uma flag de atenção.

#### 2. Os 3 Ritos Ágeis no Linear

##### Rito 1: Refinamento de Backlog & Fatiamento (Grooming)
- Realizado no meio da sprint pelo Tech Lead e Product Manager.
- O PRD do próximo Épico é lido e fatiado em **Issues Atômicas**:
  - *Regra de Atomicidade:* Nenhuma issue deve demorar mais de 1 ou 2 dias para ser implementada pelo agente/engenheiro. Tarefas grandes devem virar sub-issues (`Sub-tasks`).

##### Rito 2: Sprint Planning (Planejamento do Ciclo)
- Com base no **Velocity Histórico** (gráfico nativo do Linear que calcula a média de pontos entregues nos últimos 3 ciclos), a equipe seleciona as tarefas do `Backlog` para o `Active Cycle`.
- **Regra do Escopo Congelado:** Uma vez iniciado o ciclo, novos cards só entram se forem bugs críticos (`Urgent`) e se outro card de peso equivalente for removido e retornado ao backlog.

##### Rito 3: Monitoramento Contínuo com Burndown e Scope Graph
- O Linear gera automaticamente dois gráficos vitais:
  - **Burndown Chart:** Mostra se a velocidade de queima de pontos está alinhada para terminar no prazo.
  - **Scope Graph:** Mostra se foram adicionadas tarefas extras no meio do ciclo (identificando *Scope Creep*).

---

---

## 8. Troubleshooting & Dúvidas Frequentes

### 1. O servidor MCP do Linear ou GitHub não conecta (ícone vermelho no Orca)
- **Causa:** Node.js/npx desatualizado ou token de API incorreto/expirado.
- **Solução:** No terminal, teste rodar manualmente:
  ```bash
  npx -y @modelcontextprotocol/server-linear
  ```
  Certifique-se de que a variável `LINEAR_API_KEY` está preenchida corretamente sem aspas extras.

### 2. "Resource not found" ao tentar buscar issues via MCP
- **Causa:** O Personal Access Token do Linear não tem permissão no Workspace desejado ou você faz parte de múltiplos workspaces.
- **Solução:** No Linear, gere o token especificamente no Workspace em que os projetos estão alocados.

### 3. O Orca não detecta o arquivo `.mcp.json`
- **Causa:** O arquivo foi criado na subpasta e não na raiz do repositório aberto no Orca.
- **Solução:** Coloque `.mcp.json` na raiz da pasta que você abriu no Orca (`File -> Open Project`) ou acesse `Settings -> Repository -> MCP Configs -> Add Server`.

### 4. Conflito de portas no preview do navegador
- **Causa:** Dois worktrees rodando o servidor de desenvolvimento na mesma porta (ex: `localhost:3000`).
- **Solução:** No segundo worktree, passe a porta explicitamente: `npm run dev -- --port 3001`.

---
*Documento preparado para apresentação técnica e treinamento de times de engenharia.*
