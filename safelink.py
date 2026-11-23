#!/usr/bin/env python3
"""SafeLink CLI - análise de reputação de URLs.

Consulta o Google Safe Browsing (v4) e o VirusTotal (v3) e combina as duas
respostas em um único veredito: SEGURO, SUSPEITO, MALICIOSO ou INCONCLUSIVO.

Uso:
    export GSB_API_KEY="..."   # chave da API Safe Browsing
    export VT_API_KEY="..."    # chave da API do VirusTotal
    python safelink.py "https://exemplo.com/pagina"

Códigos de saída (úteis em scripts):
    0 = SEGURO | 1 = SUSPEITO | 2 = MALICIOSO | 3 = INCONCLUSIVO | 4 = erro de uso
"""
import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests

# --------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VT_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 15                 # segundos por requisição
DEFAULT_THRESHOLD = 3        # nº mínimo de motores do VirusTotal para "MALICIOSO"
POLL_ATTEMPTS = 4            # tentativas de consulta a uma análise recém-enviada
POLL_INTERVAL = 15           # segundos entre requisições ao VirusTotal (cota gratuita: 4 por minuto)

SEGURO, SUSPEITO, MALICIOSO, INCONCLUSIVO = "SEGURO", "SUSPEITO", "MALICIOSO", "INCONCLUSIVO"
EXIT_CODES = {SEGURO: 0, SUSPEITO: 1, MALICIOSO: 2, INCONCLUSIVO: 3}
EXIT_USAGE = 4

COLORS = {SEGURO: "\033[32m", SUSPEITO: "\033[33m", MALICIOSO: "\033[31m", INCONCLUSIVO: "\033[36m"}
RESET = "\033[0m"


# --------------------------------------------------------------------------
# Modelos de dados
# --------------------------------------------------------------------------
@dataclass
class GSBResult:
    """Resposta do Google Safe Browsing."""
    ok: bool
    threats: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class VTResult:
    """Resposta do VirusTotal (contagem de motores por categoria)."""
    ok: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    error: Optional[str] = None

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected


@dataclass
class Verdict:
    category: str
    reasons: List[str]
    divergence: bool
    threshold: int


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------
def normalize_url(raw: str) -> str:
    """Valida a URL. Exige esquema http/https e host (não adivinha o esquema)."""
    url = raw.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL inválida: informe o endereço completo, ex.: https://exemplo.com")
    return url


def vt_url_id(url: str) -> str:
    """Identificador de URL da API v3 do VirusTotal: base64 URL-safe, sem preenchimento '='."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _http(session, method: str, url: str, **kwargs):
    """Faz a requisição sem vazar a chave de API em mensagens de erro.

    As exceções do `requests` costumam incluir a URL completa (com `?key=...`),
    por isso só o nome do tipo da exceção é propagado.
    """
    try:
        return session.request(method, url, timeout=TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        raise RuntimeError(f"falha de rede ({type(exc).__name__})") from None


def _http_error_text(status: int) -> str:
    known = {400: "requisição rejeitada", 401: "chave de API inválida",
             403: "acesso negado (verifique a chave e as permissões)",
             429: "cota de requisições excedida"}
    return f"HTTP {status}" + (f" - {known[status]}" if status in known else "")


# --------------------------------------------------------------------------
# Fontes de inteligência
# --------------------------------------------------------------------------
def query_google(url: str, api_key: Optional[str], session) -> GSBResult:
    """Consulta o endpoint threatMatches:find do Safe Browsing v4."""
    if not api_key:
        return GSBResult(False, error="chave GSB_API_KEY não configurada")
    body = {
        "client": {"clientId": "safelink-cli", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = _http(session, "POST", GSB_ENDPOINT, params={"key": api_key}, json=body)
    except RuntimeError as exc:
        return GSBResult(False, error=str(exc))
    if resp.status_code != 200:
        return GSBResult(False, error=_http_error_text(resp.status_code))
    try:
        data = resp.json()
    except ValueError:
        return GSBResult(False, error="resposta não é um JSON válido")
    # Corpo vazio ({}) significa "nenhuma correspondência" (URL não listada).
    threats = sorted({m.get("threatType", "UNKNOWN") for m in data.get("matches", [])})
    return GSBResult(True, threats=threats)


def _vt_stats_to_result(stats: dict) -> VTResult:
    res = VTResult(
        ok=True,
        malicious=int(stats.get("malicious", 0)),
        suspicious=int(stats.get("suspicious", 0)),
        harmless=int(stats.get("harmless", 0)),
        undetected=int(stats.get("undetected", 0)),
    )
    if res.total == 0:
        return VTResult(False, error="nenhum motor retornou resultado para esta URL")
    return res


def query_virustotal(url: str, api_key: Optional[str], session,
                     poll_attempts: int = POLL_ATTEMPTS,
                     poll_interval: float = POLL_INTERVAL,
                     sleep=time.sleep) -> VTResult:
    """Obtém o relatório da URL; se ela nunca foi analisada (404), envia e aguarda."""
    if not api_key:
        return VTResult(False, error="chave VT_API_KEY não configurada")
    headers = {"x-apikey": api_key}
    try:
        resp = _http(session, "GET", f"{VT_BASE}/urls/{vt_url_id(url)}", headers=headers)
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            return _vt_stats_to_result(attrs.get("last_analysis_stats", {}))
        if resp.status_code != 404:
            return VTResult(False, error=_http_error_text(resp.status_code))

        # URL desconhecida: solicita uma nova análise. As pausas de `poll_interval`
        # entre requisições mantêm o ritmo dentro da cota gratuita (4 por minuto).
        sleep(poll_interval)
        resp = _http(session, "POST", f"{VT_BASE}/urls", headers=headers, data={"url": url})
        if resp.status_code != 200:
            return VTResult(False, error=_http_error_text(resp.status_code))
        analysis_id = resp.json().get("data", {}).get("id")
        if not analysis_id:
            return VTResult(False, error="resposta de envio sem identificador de análise")

        for _ in range(poll_attempts):
            sleep(poll_interval)
            resp = _http(session, "GET", f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
            if resp.status_code != 200:
                return VTResult(False, error=_http_error_text(resp.status_code))
            attrs = resp.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                return _vt_stats_to_result(attrs.get("stats", {}))
        return VTResult(False, error="análise não concluída no tempo de espera")
    except RuntimeError as exc:
        return VTResult(False, error=str(exc))
    except ValueError:
        return VTResult(False, error="resposta não é um JSON válido")


# --------------------------------------------------------------------------
# Lógica de classificação
# --------------------------------------------------------------------------
def classify(gsb: GSBResult, vt: VTResult, threshold: int = DEFAULT_THRESHOLD) -> Verdict:
    """Combina as duas fontes em um veredito.

    Regras, avaliadas nesta ordem:
      R1 MALICIOSO    : o Google lista a URL, OU o VirusTotal tem >= `threshold`
                        motores "malicious".
      R2 SUSPEITO     : (sem R1) o VirusTotal tem de 1 a threshold-1 motores
                        "malicious", OU ao menos 1 motor "suspicious".
      R3 SEGURO       : (sem R1/R2) as DUAS fontes responderam e nenhuma sinalizou.
      R4 INCONCLUSIVO : qualquer outro caso, isto é, falta uma fonte e a outra
                        não trouxe evidência de ameaça. Nunca se declara SEGURO
                        com informação incompleta.
    """
    gsb_hit = gsb.ok and bool(gsb.threats)
    vt_high = vt.ok and vt.malicious >= threshold
    vt_low = vt.ok and ((0 < vt.malicious < threshold) or vt.suspicious > 0)

    reasons: List[str] = []
    if gsb.ok:
        reasons.append("Google Safe Browsing: ameaça listada (" + ", ".join(gsb.threats) + ")"
                       if gsb_hit else "Google Safe Browsing: URL não listada")
    else:
        reasons.append(f"Google Safe Browsing indisponível: {gsb.error}")
    if vt.ok:
        reasons.append(f"VirusTotal: {vt.malicious} malicioso(s), {vt.suspicious} suspeito(s), "
                       f"{vt.harmless} inofensivo(s), {vt.undetected} sem detecção "
                       f"(limiar de malicioso = {threshold})")
    else:
        reasons.append(f"VirusTotal indisponível: {vt.error}")

    if gsb_hit or vt_high:
        category = MALICIOSO
    elif vt_low:
        category = SUSPEITO
    elif gsb.ok and vt.ok:
        category = SEGURO
    else:
        category = INCONCLUSIVO

    # Divergência: as duas fontes responderam, mas uma aponta ameaça e a outra não.
    divergence = gsb.ok and vt.ok and (gsb_hit != (vt.malicious > 0))
    if divergence:
        reasons.append("Atenção: as fontes divergem; a regra R1/R2 prevaleceu sobre a fonte que não detectou")
    return Verdict(category, reasons, divergence, threshold)


# --------------------------------------------------------------------------
# Saída
# --------------------------------------------------------------------------
def format_report(url: str, verdict: Verdict, use_color: bool) -> str:
    label = verdict.category
    if use_color:
        label = f"{COLORS[verdict.category]}{label}{RESET}"
    lines = [f"URL: {url}", f"Veredito: {label}", "Detalhes:"]
    lines += [f"  - {r}" for r in verdict.reasons]
    return "\n".join(lines)


def format_json(url: str, verdict: Verdict, gsb: GSBResult, vt: VTResult) -> str:
    return json.dumps({
        "url": url,
        "veredito": verdict.category,
        "limiar_malicioso": verdict.threshold,
        "divergencia": verdict.divergence,
        "motivos": verdict.reasons,
        "google": {"ok": gsb.ok, "ameacas": gsb.threats, "erro": gsb.error},
        "virustotal": {"ok": vt.ok, "malicioso": vt.malicious, "suspeito": vt.suspicious,
                       "inofensivo": vt.harmless, "sem_deteccao": vt.undetected, "erro": vt.error},
    }, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safelink",
        description="Verifica a reputação de uma URL no Google Safe Browsing e no VirusTotal.")
    p.add_argument("url", help="URL completa a verificar (http:// ou https://)")
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                   help=f"motores do VirusTotal necessários para MALICIOSO (padrão: {DEFAULT_THRESHOLD})")
    p.add_argument("--json", action="store_true", help="imprime o resultado em JSON")
    p.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
    return p


def main(argv=None, session=None, env=None, sleep=time.sleep, stream=None) -> int:
    env = os.environ if env is None else env
    stream = sys.stdout if stream is None else stream
    args = build_parser().parse_args(argv)

    if args.threshold < 1:
        print("Erro: --threshold deve ser >= 1", file=sys.stderr)
        return EXIT_USAGE
    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return EXIT_USAGE
    gsb_key, vt_key = env.get("GSB_API_KEY"), env.get("VT_API_KEY")
    if not gsb_key and not vt_key:
        print("Erro: defina GSB_API_KEY e/ou VT_API_KEY no ambiente.", file=sys.stderr)
        return EXIT_USAGE

    session = session or requests.Session()
    gsb = query_google(url, gsb_key, session)
    vt = query_virustotal(url, vt_key, session, sleep=sleep)
    verdict = classify(gsb, vt, args.threshold)

    if args.json:
        print(format_json(url, verdict, gsb, vt), file=stream)
    else:
        use_color = (not args.no_color and "NO_COLOR" not in env
                     and hasattr(stream, "isatty") and stream.isatty())
        if use_color and os.name == "nt":
            os.system("")  # habilita sequências ANSI no terminal do Windows 10+
        print(format_report(url, verdict, use_color), file=stream)
    return EXIT_CODES[verdict.category]


if __name__ == "__main__":
    sys.exit(main())
