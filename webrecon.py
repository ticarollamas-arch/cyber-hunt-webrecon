#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hunt Web Recon — Varredura Profunda e Ampla (Discovery Total).

Este script realiza uma varredura abrangente no alvo, sem filtros rígidos prévios,
mapeando tudo o que responde (status 200, 403, 301, 302, etc.), headers, 
tecnologias, cookies e uma lista expandida de caminhos e arquivos comuns.

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

PAUSA = 1.0   # Pausa para ser eficiente mas respeitar o servidor
UA = "CyberHuntRecon/2.0 (+security-research; deep-discovery)"

# Lista ampla e profunda de caminhos e arquivos para descoberta total
CAMINHOS_EXTENDIDOS = [
    # Configurações e Arquivos Sensíveis
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries", "/.htaccess", "/.htpasswd",
    "/config.json", "/config.php", "/config.php.bak", "/configuration.php",
    "/settings.py", "/database.sql", "/db.sql", "/backup.zip", "/backup.tar.gz",
    "/backup.sql", "/old/", "/test/", "/temp/", "/tmp/", "/phpinfo.php",
    # Painéis Administrativos e Logins
    "/admin/", "/administrator/", "/login", "/wp-login.php", "/wp-admin/",
    "/dashboard", "/panel/", "/manage/", "/auth/", "/api/login",
    # Arquivos de Informação e Padrão
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml", "/package.json", "/composer.json",
    # APIs, Documentações e Endpoints Modernos
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/swagger/", "/swagger.json",
    "/swagger/v1/swagger.json", "/openapi.json", "/docs/", "/v1/", "/v2/",
    "/actuator", "/actuator/env", "/actuator/health", "/health", "/metrics"
]


def confirmar_escopo(alvo):
    print(f"\nAlvo: {alvo}")
    print("Antes de continuar, confirme (a responsabilidade é sua):")
    p1 = input("  Este domínio está EXPLÍCITO no escopo do programa? (s/n): ").strip().lower()
    p2 = input("  O programa AUTORIZA teste/scan automatizado? (s/n): ").strip().lower()
    if not (p1.startswith("s") and p2.startswith("s")):
        print("\nPARE. Sem escopo explícito e autorização de scan, não rode.")
        return False
    return True


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
            return r.status, dict(r.headers), r.read(1500)
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
    print("CYBER HUNT WEB RECON — Varredura Profunda Total")
    print("=" * 60)

    # 1. Informações Gerais da Raiz e TLS
    print("\n[1] Analisando Conexão e Raiz do Alvo...")
    tls = checar_tls(host)
    print(f"    Versão TLS: {tls}")
    if isinstance(tls, str) and ("TLSv1.0" in tls or "TLSv1.1" in tls):
        achados.append(("TLS obsoleto", f"Servidor negocia {tls}", "media"))

    status_raiz, headers_raiz, corpo_raiz = fetch(alvo)
    time.sleep(PAUSA)
    
    if status_raiz is None:
        print(f"    [!] Erro crítico ao conectar na raiz: {headers_raiz.get('_erro')}")
        return achados

    print(f"    Status HTTP da Raiz: {status_raiz}")
    
    low_raiz = {k.lower(): v for k, v in headers_raiz.items()}
    
    # Servidor / Tecnologias via Header
    server = low_raiz.get("server", "Desconhecido")
    powered = low_raiz.get("x-powered-by", None)
    print(f"    Servidor Identificado: {server}")
    if powered:
        print(f"    X-Powered-By: {powered}")
        achados.append(("Tecnologia exposta (X-Powered-By)", f"Header revela: {powered}", "baixa"))

    # Cookies na raiz
    setc = low_raiz.get("set-cookie", "")
    if setc:
        print(f"    Cookies detectados na raiz.")
        if "secure" not in setc.lower():
            achados.append(("Cookie sem flag Secure", "Cookie inicial sem flag Secure.", "baixa"))
        if "httponly" not in setc.lower():
            achados.append(("Cookie sem flag HttpOnly", "Cookie inicial sem flag HttpOnly.", "baixa"))

    # Cabeçalhos de segurança ausentes (Informativo completo)
    sec_headers_esperados = [
        "strict-transport-security", "content-security-policy", 
        "x-frame-options", "x-content-type-options", "referrer-policy"
    ]
    ausentes = [sh for sh in sec_headers_esperados if sh not in low_raiz]
    if ausentes:
        print(f"    Cabeçalhos ausentes: {', '.join(ausentes)}")
        achados.append(("Cabeçalhos de segurança ausentes", f"Faltam: {', '.join(ausentes)}", "baixa"))

    # 2. Varredura Ampla e Profunda (Qualquer resposta útil)
    print(f"\n[2] Executando varredura profunda em {len(CAMINHOS_EXTENDIDOS)} caminhos...")
    for c in CAMINHOS_EXTENDIDOS:
        url = alvo.rstrip("/") + c
        st, _, corpo = fetch(url)
        time.sleep(PAUSA)

        if st is not None:
            # Captura tudo o que for interessante: 200 (OK), 403 (Proibido/Existe), 301/302 (Redirecionamento)
            if st in (200, 403, 301, 302, 401):
                print(f"    [ENCONTRADO] {c} — HTTP {st}")
                
                # Definir severidade com base no tipo de caminho e status
                if st == 200:
                    if any(k in c for k in [".env", ".git", "backup", "sql", "htpasswd"]):
                        sev = "alta"
                        desc = "Arquivo altamente sensível exposto publicamente com HTTP 200."
                    elif any(k in c for k in ["api", "graphql", "swagger", "actuator"]):
                        sev = "media"
                        desc = "Endpoint de API ou documentação exposto publicamente."
                    else:
                        sev = "baixa"
                        desc = "Recurso acessível publicamente (HTTP 200)."
                elif st == 403:
                    sev = "baixa"
                    desc = "Caminho existe mas o acesso é negado (403 Forbidden)."
                else:
                    sev = "baixa"
                    desc = f"Caminho respondeu com código de redirecionamento/auth ({st})."

                achados.append((f"Caminho mapeado: {c} (HTTP {st})", desc, sev))

    return achados


def relatar(achados, alvo, saida=None):
    print("\n" + "=" * 60)
    if not achados:
        print("RESUMO — Nenhum item mapeado.")
    else:
        print(f"RESUMO — Total de {len(achados)} ocorrência(s) encontrada(s):")
        ordem = {"alta": 0, "media": 1, "baixa": 2}
        for titulo, desc, sev in sorted(achados, key=lambda x: ordem[x[2]]):
            print(f"\n[{sev.upper()}] {titulo}")
            print(f"    {desc}")

    print("\n" + "-" * 60)
    print("Varredura profunda concluída. Analise os achados e valide o contexto.")

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

