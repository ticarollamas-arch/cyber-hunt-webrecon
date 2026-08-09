# Cyber Hunt Web Recon

Análise passiva de configuração de segurança de um site: cabeçalhos de segurança, flags de cookie, versão de TLS e caminhos sensíveis expostos. Complementa os scanners de código estático — este olha a aplicação **rodando**, sem precisar do código-fonte.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green)

> **Reconhecimento passivo.** Não envia payload de ataque, não explora nada, vai devagar (uma requisição por vez, com pausa). É o tipo de análise que a maioria dos programas de bug bounty aceita.

## ⚠ Antes de usar — obrigatório

Só rode contra um alvo se **as duas coisas** forem verdade:

1. O domínio está **explícito no escopo** do programa de bug bounty.
2. O programa **autoriza teste ou scan automatizado** (muitos proíbem ou limitam a taxa — leia a política).

Rodar em alvo não autorizado é acesso indevido, com consequências legais — ainda mais em órgãos de governo. A ferramenta pergunta isso antes de rodar, mas a responsabilidade é sua.

## Uso

```bash
python3 webrecon.py https://alvo-autorizado.com
python3 webrecon.py https://alvo-autorizado.com --json relatorio.json
```

## O que verifica

| Item | O que olha |
|---|---|
| TLS | versão negociada (alerta em TLS 1.0/1.1) |
| Cabeçalhos | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookies | flags Secure, HttpOnly, SameSite |
| Servidor | versão exposta no header Server |
| Caminhos | .git, .env, backups e outros arquivos que não deveriam estar públicos |

## Sobre a severidade

A ferramenta classifica em alta/média/baixa, mas seja honesta no report:
**header de segurança ausente, sozinho, costuma ser severidade baixa** — e muitos programas nem aceitam como achado válido. O que rende de verdade é `.git`/`.env` exposto (pode conter credencial) ou combinação de fatores. Confirme o impacto real antes de reportar.

## Limitações

- É passivo: não encontra falhas de lógica, injeção ou autenticação — essas exigem teste ativo, que tem regras mais restritas.
- Um achado aqui é ponto de partida para investigação humana, não veredito.

## Licença

MIT
