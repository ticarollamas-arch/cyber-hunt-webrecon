#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hunt Web Recon — Foco Extremo em P1 / P2 (Arquivos e Endpoints Críticos).

Filtra ruídos, cabeçalhos ausentes e cookies, focando estritamente em potenciais
vulnerabilidades de impacto alto ou médio (como .env, .git, backups e endpoints expostos).

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

PAUSA = 1.5   # segundos entre requisições
UA = "CyberHuntRecon/1.0 (+security-research; passive)"

# Caminhos altamente sensíveis que indicam falhas de configuração ou vazamentos graves (P1/P2)
CAMINHOS_CRITICOS = [
    "/.git/config", "/.env", "/.svn/entries", "/config.php.bak",
    "/backup.zip", "/.DS_Store", "/wp-config.php.bak", "/database.sql",
    "/swagger/v1/swagger.json", "/api/v1/", "/graphql", "/actuator/env", "/actuator/health"
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
    print("CYBER HUNT WEB RECON — Foco Exclusivo P1 / P2 (Críticos)")
    print("=" * 60)

    # 1. TLS Obsoleto
    print("\n[1] Verificando versão de TLS...")
    tls = checar_tls(host)
    print(f"    {tls}")
    if isinstance(tls, str) and ("TLSv1.0" in tls or "TLSv1.1" in tls):
        achados.append(("TLS obsoleto detectado", f"Servidor negocia {tls}", "media"))

    # 2. Varredura Profunda de Caminhos Críticos (Foco Principal)
    print("\n[2] Executando busca profunda de arquivos e endpoints sensíveis (P1/P2)...")
    for c in CAMINHOS_CRITICOS:
        url = alvo.rstrip("/") + c
        st, _, corpo = fetch(url)
        time.sleep(PAUSA)
        
        # Filtro estrito: Ignorar 404, 403 genéricos ou redirecionamentos para páginas de erro padrão (soft 404)
        if st == 200 and corpo:
            conteudo_str = corpo.decode("utf-8", errors="ignore").lower()
            if "<html" in conteudo_str and ("not found" in conteudo_str or "404" in conteudo_str):
                continue
                
            print(f"    [!] POTENCIAL EXPOSIÇÃO CRÍTICA: {c} (HTTP 200)")
            sev = "alta" if any(k in c for k in [".git", ".env", "backup", "sql", "actuator"]) else "media"
            achados.append((f"Arquivo/Endpoint sensível exposto: {c}", "Acessível publicamente com código HTTP 200.", sev))

    return achados


def relatar(achados, alvo, saida=None):
    print("\n" + "=" * 60)
    if not achados:
        print("RESUMO — Nenhum achado crítico de severidade Média ou Alta (P1/P2) detectado.")
        print("O alvo está blindado contra os caminhos testados nesta varredura.")
    else:
        print(f"RESUMO — {len(achados)} potencial(is) achado(s) crítico(s) (P1/P2)")
        ordem = {"alta": 0, "media": 1}
        for titulo, desc, sev in sorted(achados, key=lambda x: ordem[x[2]]):
            print(f"\n[{sev.upper()}] {titulo}")
            print(f"    {desc}")
            
    print("\n" + "-" * 60)
    print("Filtro aplicado: Verificação de cookies e cabeçalhos ausentes removidos.")

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

