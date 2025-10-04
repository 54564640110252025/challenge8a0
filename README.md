# 🛡️ WolfGuard Antivírus

> **Status:** Confidencial · Documento técnico 
> **Data:** 04 de outubro de 2025  
> **Compilado por:** WolfGuard  
> **Website Oficial:** https://wolfguard.com.br  
> **Suporte:** wolfguardsuporte@gmail.com

<p align="center">
  <a href="https://wolfguard.com.br"><img src="https://img.shields.io/badge/site-wolfguard.com.br-informational" alt="Site"></a>
  <img src="https://img.shields.io/badge/Windows-10%2F11%20x64-blue" alt="Windows 10/11 x64">
  <img src="https://img.shields.io/badge/estado-Ativo-success" alt="Status">
  <img src="https://img.shields.io/badge/antiransomware-8%E2%80%930-brightgreen" alt="Antiransomware 8-0">
  <img src="https://wolfguard.com.br/#download" alt="Installer">
</p>

---

## 📋 Sumário (TOC)
- [Visão Geral](#-visão-geral)
- [Destaques](#-destaques)
- [Instalação & Configuração](#-instalação--configuração)
- [Execução](#-execução)
- [Arquitetura do Sistema](#-arquitetura-do-sistema)
- [Módulos de Proteção](#-módulos-de-proteção)
- [Interface & Experiência do Usuário](#-interface--experiência-do-usuário)
- [Serviço do Windows & Tray](#-serviço-do-windows--tray)
- [Configurações (antiransom_config.json)](#-configurações-antiransom_configjson)
- [Whitelist & Verificação de Assinatura](#-whitelist--verificação-de-assinatura)
- [Quarentena & Logs](#-quarentena--logs)
- [Resultados de Testes](#-resultados-de-testes)
- [Roadmap](#-roadmap)
- [FAQ](#-faq)
- [Suporte](#-suporte)
- [Créditos & Equipe](#-créditos--equipe)
- [Licença](#-licença)

---

## 🔎 Visão Geral

O **WolfGuard Antivírus** é uma suíte de cibersegurança moderna para **Windows** com proteção multicamadas contra um amplo espectro de ameaças, com foco em **ransomware** e **ataques de dia zero**. Combina **assinaturas**, **heurísticas avançadas**, **monitoramento comportamental em tempo real**, **bloqueio de downloads suspeitos**, **verificação de reputação/assinatura de executáveis** e um **sistema Honeypot** com **lockdown** (rede/USB) de reação rápida.

> **Diferenciais**: baixo impacto de performance, integração nativa com o Windows via `ctypes`/WMI/Win32, cache de verificação de assinatura (ultra‑rápido), UI moderna (PyQt5/PySide6), e um conjunto robusto de módulos (tempo real, antiransomware, USB, quarentena, YARA, reputação em nuvem, etc.).

---

## ✨ Destaques

- **Defesa em Profundidade**: múltiplos motores operando em camadas (kernel/API nativa + aplicação).  
- **Honeypot Inteligente**: detecção precoce por arquivos‑isca e **lockdown** (desligar rede + ejetar USB) com atalho de recuperação.  
- **Análise Estática + ML**: inspeção PE + classificação assistida para *zero‑day like* (documentado na apresentação).  
- **Tempo Real de Verdade**: filesystem, processos (WMI), memória, rede e downloads.  
- **USB Hardening**: varredura e bloqueio preventivo de mídias removíveis.  
- **YARA Integrado**: suporte a regras customizadas.  
- **Quarentena Segura**: isolamento criptografado e gerenciamento completo.  
- **UX Profissional**: dashboard, logs detalhados, *system tray*, hotkeys, configurações por JSON.  

---

## ⚙️ Instalação & Configuração

1. **Download**: obtenha o instalador oficial em **[wolfguard.com.br](https://wolfguard.com.br)**.  
2. **Instalação**: execute o instalador e escolha o diretório de destino ou use o padrão:  
   `C:\Program Files (x86)\WolfGuard`
3. **Atalho**: um atalho é criado na área de trabalho.
4. **Serviço do Windows**: o instalador registra e inicia o serviço `WolfGuardAntivirus` para garantir proteção desde a inicialização.
5. **Primeira Execução**: proteção em tempo real é habilitada por padrão.


```

---

## ▶️ Execução

- **Modo Serviço**: inicia automaticamente como `WolfGuardAntivirus` (proteção contínua).  
- **Modo Tray/GUI**: interface leve na bandeja do sistema com ações rápidas (scan, quarentena, status, iniciar/parar serviço).  
- **Single Instance**: controle via *mutex* global para evitar múltiplas instâncias.  
- **Privilégios**: elevação automática quando necessário (UAC).  
- **Atalhos de Teclado**:
  - `F3`: mostrar/ocultar janela leve do Anti‑Ransom (overlay).  
  - `F4`: **restaurar Rede e USB** após lockdown do Honeypot.  

---

## 🧩 Arquitetura do Sistema

**Camada Kernel/APIs (ctypes/Win32/WMI)**  
Intercepta/observa criação de processos (WMI), interage com WinTrust para assinatura, manipula serviços, rede e USB, e integrações do sistema.

**Camada de Aplicação (Python)**  
Core de decisão, correlação de sinais e orquestração de módulos: tempo real, heurísticas, reputação, quarentena, UI, logs e política.

**Módulos Especializados**  
- Proteção em Tempo Real & Download Blocker  
- Escudo Anti‑Ransomware (Heurísticas + Honeypot)  
- Verificação Inteligente (Estática + ML + Reputação em nuvem)  
- Proteção USB e Bloqueio de Scripts  
- Regras **YARA**  
- Quarentena e Relatórios/Logs

---

## 🛡️ Módulos de Proteção

### 4.1 Proteção em Tempo Real
- **Criação de Processos (WMI)**: *watchers* reagem instantaneamente a novos processos; política agressiva opcional **mata** e/ou **remove** executáveis inseguros.  
- **Bloqueio de Scripts**: `.ps1`, `.cmd`, `.bat`, `.vbs`, `.js`, `.py` conforme política (inclui detecção de *legit system scripts* por caminho do Windows).  
- **Downloads Watcher**: monitora diretórios sensíveis (Downloads, Desktop, Documents, Pictures) e **deleta** automaticamente scripts perigosos e **EXEs não assinados**.  
- **Foco do Usuário**: *focus monitor* scanneia a pasta da janela ativa para alertar/bloquear rapidamente artefatos suspeitos.  

### 4.2 Escudo Anti‑Ransomware & Honeypot
- **Heurística**: entropia alta, extensões suspeitas, criação de *ransom notes*, velocidade de modificação de arquivos.  
- **Honeypot**: arquivos‑isca estratégicos (ex.: `senhas_bancarias.txt`, `dados_pix.txt`, `backup_senhas.txt`).  
- **Lockdown**: ao tocar nos honeypots, a defesa pode **desativar rede** (Wi‑Fi/Ethernet), **ejetar USB**, **encerrar o processo ofensivo** e emitir **alerta**; `F4` reverte rede/USB.  

### 4.3 Verificação Inteligente & Nuvem
- **Análise Estática PE**: inspeção de seções, *imports* críticos e empacotadores.  
- **Machine Learning Assistido**: classificação combinada com sinais de outros motores.  
- **Reputação/Nuvem**: submissão de *hashes* anônimos para verificação de prevalência.  
- **YARA**: suporte a regras customizadas.  

### 4.4 Proteção de Dispositivos Externos & Downloads
- **USB**: varredura automática em conexão; bloqueio de *autorun* e executáveis suspeitos.  
- **Downloads**: quarentena/remoção preventiva de arquivos perigosos recém‑criados/modificados nas pastas monitoradas.  

---

## 🖥️ Interface & Experiência do Usuário

- **Fancy Overlay (PySide6)**: janela compacta, translúcida, com monitor de eventos em tempo real, *toggles* e feedback instantâneo; acesso por `F3`.  
- **Quarentena (PyQt5)**: página dedicada, tabela com ID/ameaça/caminho/tamanho/data e ações.  
- **Tray**: ícone na bandeja com menu (Scan, Quarentena, Restaurar Rede/USB, Iniciar Serviço, Sair) e *toasts* informativos.  
- **Logs Detalhados**: visualização dedicada e diálogo com histórico completo.  

---

## 🧰 Serviço do Windows & Tray

- **Serviço `WolfGuardAntivirus`**: executa ciclos de *scan* e monitoração; agenda varreduras periódicas; responde a hotkeys do sistema (ex.: `F4`).  
- **Tray Controller**: ícone, menu de contexto, *balloon tips* e *double‑click* para status.  
- **Single Instance + Hotkey**: `F3` (mostrar/ocultar) e menu de sair seguro (encerra threads, observadores e focos).  

---

## 🧾 Configurações (`antiransom_config.json`)

Local: `%APPDATA%\WolfGuard\antiransom_config.json`

```json
{
  "block_unsigned_exe": true,
  "block_js": true,
  "block_ps1": true,
  "block_cmd": true,
  "block_bat": true,
  "block_vbs": true,
  "block_py": false,
  "kill_running_offenders": true,
  "downloads_block_js": true,
  "downloads_block_ps1": true,
  "downloads_block_cmd": true,
  "downloads_block_bat": true,
  "downloads_block_vbs": true,
  "downloads_block_py": false,
  "downloads_block_unsigned_exe": true,
  "auto_scan_enabled": true,
  "scan_user_focus": true,
  "aggressive_mode": true,
  "scan_interval": 5
}
```

> **Dica**: defina `aggressive_mode` e `kill_running_offenders` para *hardening* máximo (mata processos ofensores e remove EXEs não assinados automaticamente).

---

## ✅ Whitelist & Verificação de Assinatura

- **Whitelist Inteligente**: combina *paths* do sistema (Windows, Program Files, drivers, etc.), *apps* conhecidos e *scripts* próprios (`wolf.py`, `wolf5.py`, etc.).  
- **WinTrust (Assinatura Digital)**: verificação via **WinVerifyTrust** com **cache global** ultra‑rápido (até 10k entradas); cai para heurísticas seguras quando necessário.  
- **Regras para Scripts do Sistema**: PowerShell/CMD/WSH permitidos **somente** quando apontam para *paths* legítimos do Windows; caso contrário, **bloqueio**.  

---

## 🧪 Quarentena & Logs

- **Quarentena**: isolamento seguro de artefatos, com tabela de gerenciamento e opções de restauração/remoção.  
- **Logs**: arquivos dedicados no diretório de dados do app/serviço; janela “Logs Detalhados” para análise rápida.  
- **Notificações**: *toasts* informativos (WinNotify/Toaster/Plyer – automático por disponibilidade).  

### Locais (padrão)
- App data: `%APPDATA%\WolfGuardAV` (serviço) e `%APPDATA%\WolfGuard` (GUI).  
- Log do serviço: `service.log`.  
- Quarentena: subpasta dedicada interna ao app data.

---

## 🧪 Resultados de Testes

- **Cenário**: laboratório controlado por **PRIDE Security** e **Prof. Fabio Silva Pires de Oliveira**.  
- **Amostras**: **8** variantes de **ransomware**.  
- **Resultado**: **8–0** a favor do **WolfGuard** (todas neutralizadas **antes** de dano persistente).

> **Metodologia (resumo)**: execução em *sandbox* Windows limpa, com monitoramento de filesystem/processos, validação de lockdown por Honeypot e verificação de integridade pós‑teste.  
> **Nota**: amostras e *IoCs* específicos são mantidos sob confidencialidade; replicações devem ocorrer em ambientes isolados.

---

## 🗺️ Roadmap

- Aprimoramento do classificador (ML) com *feedback loop* supervisionado.  
- Modo *Kernel Helper* para reforço de ganchos e telemetria de baixo nível.  
- Gerenciador de regras **YARA** com *sync* de repositórios.  
- Melhorias de UX (acessibilidade, temas, perfis de política).  
- Exportação de relatórios (JSON/PDF) e integrações SIEM (WEC/Winlogbeat).  
- Mecanismo de *updates* diferenciais assinados.  

---

## ❓ FAQ

**O WolfGuard funciona sem internet?**  
Sim. Heurísticas, YARA e mecanismos locais operam offline; reputação em nuvem fica limitada.

**O que acontece no lockdown do Honeypot?**  
Rede e USB são desativadas, o processo ofensivo é finalizado e um alerta é exibido. Use `F4` para reativar.

**Posso criar regras YARA próprias?**  
Sim. O módulo aceita regras customizadas e collections corporativas.

**E se um falso positivo ocorrer?**  
Itens ficam na quarentena para análise e restauração opcional.

---

## 🆘 Suporte

- 📧 **wolfguardsuporte@gmail.com**  
- 🌐 **https://wolfguard.com.br**

> Para questões de segurança, inclua versão do produto, logs relevantes e *hashes* das amostras (não envie binários).

---

## 🙌 Créditos & Equipe

**Equipe de Desenvolvimento**: **Sarah**, **Mateus**, **Eduardo**, **Guilherme**, **Pedro**  
**Origem do Projeto**: FIAP  
**Parceiros de Teste**: **PRIDE Security**, **Prof. Fabio Silva Pires de Oliveira**

---

## 📄 Licença

Este repositório/documentação está sob **Licença Proprietária**.  
Solicite autorização por escrito antes de redistribuir ou reutilizar partes deste conteúdo.

---

> *Este README consolida o relatório técnico, a apresentação oficial e o inventário real de funcionalidades do código‑fonte (`wolf.py`/`wolf5.py`).*
