# 🛡️ WolfGuard Antivírus — Relatório Técnico & README do Projeto

> **Status:** Confidencial · Documento técnico de análise e README para uso no GitHub  
> **Data:** 04 de outubro de 2025  
> **Compilado por:** WolfGuard  
> **Website Oficial:** https://wolfguard.com.br  
> **Suporte:** wolfguardsuporte@gmail.com

<p align="center">
  <a href="https://wolfguard.com.br"><img src="https://img.shields.io/badge/site-wolfguard.com.br-informational" alt="Site"></a>
  <img src="https://img.shields.io/badge/Windows-10%2F11%20x64-blue" alt="Windows 10/11 x64">
  <img src="https://img.shields.io/badge/status-ativo-success" alt="Status">
  <img src="https://img.shields.io/badge/antiransomware-8%E2%80%930-brightgreen" alt="Antiransomware 8-0">
  <img src="https://img.shields.io/badge/build-Installer-lightgrey" alt="Installer">
</p>

---

## 📋 Sumário (TOC)
- [Visão Geral](#-visão-geral)
- [Destaques](#-destaques)
- [Instalação & Configuração](#-instalação--configuração)
- [Arquitetura do Sistema](#-arquitetura-do-sistema)
- [Módulos de Proteção](#-módulos-de-proteção)
- [Interface & Experiência do Usuário](#-interface--experiência-do-usuário)
- [Requisitos do Sistema](#-requisitos-do-sistema)
- [Segurança, Privacidade & Telemetria](#-segurança-privacidade--telemetria)
- [Resultados de Testes](#-resultados-de-testes)
- [Roadmap](#-roadmap)
- [FAQ](#-faq)
- [Suporte](#-suporte)
- [Créditos & Equipe](#-créditos--equipe)
- [Licença](#-licença)

---

## 🔎 Visão Geral

O **WolfGuard Antivírus** é uma suíte de cibersegurança moderna para **Windows** com proteção multicamadas contra um amplo espectro de ameaças, com foco em **ransomware** e **ataques de dia zero**. Combina **assinaturas**, **heurísticas avançadas**, **monitoramento comportamental em tempo real** e um **sistema Honeypot** agressivo para conter e neutralizar ameaças.

> **Diferenciais**: baixo impacto de performance, integração nativa com o Windows via `ctypes`/WMI e um conjunto robusto de módulos (tempo real, antiransomware, USB, quarentena, YARA, reputação em nuvem, etc.).

---

## ✨ Destaques

- **Defesa em Profundidade**: múltiplos motores de análise operando em camadas.
- **Honeypot Inteligente**: detecção precoce por arquivos‑isca e **lockdown imediato**.
- **Análise Estática + ML**: inspeção PE + classificação assistida para *zero-day like*.
- **Tempo Real de Verdade**: filesystem, processos, memória, rede e downloads.
- **USB Hardening**: varredura e bloqueio preventivo de mídias removíveis.
- **YARA Integrado**: suporte a regras customizadas de alto nível.
- **Quarentena Segura**: isolamento criptografado e gerenciamento completo.
- **UX Profissional**: dashboard, logs, system tray, atalhos e configurações granulares.

---

## ⚙️ Instalação & Configuração

1. **Download**: obtenha o instalador oficial em **[wolfguard.com.br](https://wolfguard.com.br)**.  
2. **Instalação**: execute o instalador e escolha o diretório de destino ou use o padrão:  
   `C:\Program Files (x86)\WolfGuard`
3. **Atalho**: um atalho para o painel do WolfGuard é criado automaticamente na área de trabalho.
4. **Serviço do Windows**: o instalador registra e inicia o serviço `WolfGuardAntivirus` para garantir proteção desde a inicialização.

### Verificação Rápida do Serviço (PowerShell)
```powershell
Get-Service -Name WolfGuardAntivirus
# Start-Service WolfGuardAntivirus
# Stop-Service  WolfGuardAntivirus
```

> **Observação**: após a instalação, o WolfGuard inicia com proteção em tempo real habilitada por padrão.

---

## 🧩 Arquitetura do Sistema

**Camada Kernel (ctypes/WINAPI)**  
Interação direta com APIs nativas do Windows para monitorar criação de processos, I/O de arquivos, alterações de registro e eventos de segurança.

**Camada de Aplicação (Python)**  
Core de decisão, correlação de sinais e orquestração de módulos: tempo real, heurísticas, reputação, quarentena, UI, logs e política.

**Módulos Especializados**  
- Proteção em Tempo Real  
- Escudo Anti‑Ransomware (Heurísticas + Honeypot)  
- Verificação Inteligente (Estática + ML + Reputação em nuvem)  
- Proteção USB e Downloads  
- Regras **YARA**  
- Quarentena e Relatórios

> *Diagrama conceitual (placeholder):* `docs/architecture.png`

---

## 🛡️ Módulos de Proteção

### 4.1 Proteção em Tempo Real
- **Sistema de Arquivos**: *watchdog* inspeciona criações/modificações; bloqueio/quarentena imediatos para indicadores maliciosos.
- **Processos**: encerramento de executáveis sem assinatura válida ou com comportamento suspeito.
- **Comportamento**: detecção de picos de CPU/I/O, renomeações em massa, *privilege escalation*.
- **Memória**: varredura de *fileless* e artefatos em runtime.
- **Rede**: inspeção de destinos e portas; bloqueio de C2 e backdoors conhecidos.

### 4.2 Escudo Anti‑Ransomware & Honeypot
- **Heurística**: entropia alta, extensões suspeitas, criação de *ransom notes*, velocidade de modificação de arquivos.
- **Honeypot**: arquivos‑isca estratégicos (ex.: `senhas_bancarias.txt`, `dados_pix.txt`, `backup_senhas.txt`).  
- **Ação de Lockdown** (gatilhada ao toque nos honeypots):
  - Desabilita **todas** as interfaces de rede (Wi‑Fi/Ethernet).
  - Ejeta **todas** as mídias removíveis.
  - Finaliza o **processo ofensivo**.
  - Emite **alerta de alta prioridade** ao usuário.
- **Atalho de Recuperação**: `F4` para reativar rapidamente rede e USB após incidente.

### 4.3 Verificação Inteligente & Nuvem
- **Análise Estática PE**: inspeção de seções, *imports* críticos e empacotadores.
- **Machine Learning Assistido**: classificação combinada com sinais de outros motores.
- **Reputação/Nuvem**: submissão de *hashes* anônimos para verificação de prevalência.
- **YARA**: suporte a regras customizadas para famílias e *tooling* avançado.

### 4.4 Proteção de Dispositivos Externos
- **USB**: varredura automática em conexão; bloqueio de scripts *autorun* e executáveis suspeitos.
- **Downloads**: monitor dedicado em pastas sensíveis; quarentena preventiva.

---

## 🖥️ Interface & Experiência do Usuário

- **Dashboard**: status em tempo real, gráficos e *timeline* de eventos.
- **Verificador de Links**: análise rápida de URLs antes do acesso.
- **IP/USB**: informações de rede (IP público/local) e gestão segura de mídias.
- **Blacklist**: bloqueio por nome/caminho de executáveis.
- **Quarentena**: isolamento criptografado, restauração (com aviso) e exclusão segura.
- **Configurações**: níveis de agressividade, bloqueios específicos, notificações e senha.
- **Tempo de Uso**: métricas e engajamento.
- **System Tray**: execução silenciosa com atalhos de ação.

---

## 🧰 Requisitos do Sistema

- **SO**: Windows 10/11 (64‑bits)  
- **CPU**: x64 atual (Intel/AMD)  
- **RAM**: 4 GB (8 GB recomendado)  
- **Armazenamento**: 500 MB livres  
- **Rede**: necessária para reputação em nuvem (funciona offline com capacidades reduzidas)

---

## 🔐 Segurança, Privacidade & Telemetria

- **Princípio do Menor Privilégio**: módulos executam com privilégios mínimos necessários.
- **Isolamento**: quarentena criptografada; operações sensíveis em *sandboxes* controladas.
- **Telemetria Opcional**: envio de *hashes* e indicadores de forma **anônima** para reputação; conteúdo de arquivos **não é enviado**.
- **Modo Offline**: detecção via heurísticas/YARA permanece ativa.

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

> *Este README consolida o relatório técnico e a apresentação oficial do WolfGuard, servindo tanto como visão executiva quanto referência operacional para stakeholders, contribuidores e auditorias técnicas.*
