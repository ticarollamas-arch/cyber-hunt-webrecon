#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hunt Web Recon — análise passiva de configuração de segurança.

Olha o que um servidor web JÁ EXPÕE publicamente: cabeçalhos de segurança,
flags de cookie, versão de TLS e alguns caminhos sensíveis comuns. NÃO envia
payload de ataque, NÃO tenta explorar nada, vai devagar (uma requisição por vez
com pausa). É reconhecimento defensivo — o tipo que a maioria dos programas de
bug bounty aceita.

ANTES DE USAR: confirme que o domínio está no escopo do programa E que o
programa autoriza teste/scan automatizado. Rodar em alvo não autorizado é
acesso indevido, com consequências legais. Esta ferramenta te pergunta isso.

Uso:
    python3 webrecon.py https://exemplo.com
    python3 webrecon.py https://exemplo.com --json relatorio.json
"""
import json
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse

PAUSA = 1.5   # segundos entre requisições — educado com o servidor
UA = "CyberHuntRecon/1.0 (+security-research; passive)"

# Cabeçalhos de segurança esperados e o que a ausência significa.
SEC_HEADERS = {
    "strict-transport-security": "Sem HSTS: navegador pode aceitar conexão HTTP insegura.",
    "content-security-policy": "Sem CSP: menos proteção contra XSS e injeção de conteúdo.",
    "x-frame-options": "Sem X-Frame-Options/CSP frame-ancestors: risco de clickjacking.",
    "x-content-type-options": "Sem X-Content-Type-Options: risco de MIME sniffing.",
    "referrer-policy": "Sem Referrer-Policy: pode vazar URL de origem.",
    "permissions-policy": "Sem Permissions-Policy: recursos do navegador sem restrição.",
}

# Caminhos comuns que NÃO deveriam estar públicos. Só um GET de leitura.
CAMINHOS = ["/.git/config", "/.env", "/.svn/entries", "/config.php.bak",
            "/backup.zip", "/.DS_Store", "/robots.txt", "/.well-known/security.txt"]


def confirmar_escopo(alvo):
    print(f"\nAlvo: {alvo}")
    print("Antes de continuar, confirme (a responsabilidade é sua):")
    p1 = input("  Este domínio está EXPLÍCITO no escopo do programa? (s/n): ").strip().lower()
    p2 = input("  O programa AUTORIZA teste/scan automatizado? (s/n): ").strip().lower()
    if not (p1.startswith("s") and p2.startswith("s")):
        print("\nPARE. Sem escopo explícito e autorização de scan, não rode.")
        print("Leia a página do programa. Rodar mesmo assim é acesso não autorizado.")
        return False
    return True


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return r.status, dict(r.headers), r.read(2048)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), b""
    except Exception as e:
        return None, {"_erro": str(e)}, b""


def checar_tls(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.version()
    except Exception as e:
        return f"[erro: {e}]"


def scan(alvo):
    achados = []
    parsed = urlparse(alvo)
    host = parsed.hostname

    print("\n" + "=" * 60)
    print("CYBER HUNT WEB RECON — análise passiva")
    print("=" * 60)

    # 1. TLS
    print("\n[1] Versão de TLS...")
    tls = checar_tls(host)
    print(f"    {tls}")
    if isinstance(tls, str) and ("TLSv1.0" in tls or "TLSv1.1" in tls):
        achados.append(("TLS obsoleto", f"Servidor negocia {tls}", "media"))

    # 2. Cabeçalhos de segurança
    print("\n[2] Cabeçalhos de segurança...")
    status, headers, _ = fetch(alvo)
    time.sleep(PAUSA)
    if status is None:
        print(f"    não foi possível conectar: {headers.get('_erro')}")
        return achados
    low = {k.lower(): v for k, v in headers.items()}
    for h, msg in SEC_HEADERS.items():
        if h not in low:
            print(f"    faltando: {h}")
            achados.append((f"Header ausente: {h}", msg, "baixa"))

    # 3. Cookies
    print("\n[3] Flags de cookie...")
    setc = low.get("set-cookie", "")
    if setc:
        if "secure" not in setc.lower():
            achados.append(("Cookie sem Secure", "Cookie pode trafegar em HTTP.", "media"))
        if "httponly" not in setc.lower():
            achados.append(("Cookie sem HttpOnly", "Cookie acessível via JavaScript (risco XSS).", "media"))
        if "samesite" not in setc.lower():
            achados.append(("Cookie sem SameSite", "Risco de CSRF.", "baixa"))
    else:
        print("    nenhum cookie na resposta inicial.")

    # 4. Banner do servidor
    srv = low.get("server", "")
    if srv:
        print(f"\n[4] Server: {srv}")
        if any(c.isdigit() for c in srv):
            achados.append(("Versão do servidor exposta", f"Header Server revela: {srv}", "baixa"))

    # 5. Caminhos sensíveis (um GET de leitura em cada)
    print("\n[5] Caminhos sensíveis expostos...")
    for c in CAMINHOS:
        url = alvo.rstrip("/") + c
        st, _, corpo = fetch(url)
        time.sleep(PAUSA)
        if st == 200 and corpo:
            print(f"    EXPOSTO: {c} (HTTP 200)")
            sev = "alta" if c in ("/.git/config", "/.env") else "media"
            achados.append((f"Arquivo exposto: {c}", "Acessível publicamente (HTTP 200).", sev))

    return achados


def relatar(achados, alvo, saida=None):
    print("\n" + "=" * 60)
    print(f"RESUMO — {len(achados)} observação(ões)")
    print("=" * 60)
    ordem = {"alta": 0, "media": 1, "baixa": 2}
    for titulo, desc, sev in sorted(achados, key=lambda x: ordem[x[2]]):
        print(f"\n[{sev.upper()}] {titulo}")
        print(f"    {desc}")
    print("\n" + "-" * 60)
    print("Estas são OBSERVAÇÕES de configuração, não vulnerabilidades comprovadas.")
    print("Confirme o impacto e verifique se o programa aceita este tipo de achado")
    print("antes de reportar. Header ausente sozinho costuma ser severidade baixa.")

    if saida:
        with open(saida, "w", encoding="utf-8") as f:
            json.dump({"alvo": alvo, "achados": [
                {"titulo": t, "descricao": d, "severidade": s} for t, d, s in achados
            ]}, f, ensure_ascii=False, indent=2)
        print(f"\nRelatório salvo em {saida}")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 0
    alvo = args[0]
    if not alvo.startswith("http"):
        print("Informe a URL completa, com https://")
        return 2
    saida = None
    if "--json" in args:
        saida = args[args.index("--json") + 1]
    if not confirmar_escopo(alvo):
        return 1
    achados = scan(alvo)
    relatar(achados, alvo, saida)
    return 0


if __name__ == "__main__":
    sys.exit(main())
