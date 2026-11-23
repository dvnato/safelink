"""Testes automatizados do SafeLink CLI.

As APIs reais NÃO são chamadas: uma sessão HTTP falsa devolve respostas
simuladas, no formato documentado pelo Google Safe Browsing v4 e pelo
VirusTotal v3. Executar com:  python -m unittest -v test_safelink
"""
import base64
import io
import json
import unittest

import requests

import safelink as sl

URL = "https://exemplo.test/login"
GSB_CLEAN = {}
GSB_HIT = {"matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM",
                         "threatEntryType": "URL", "threat": {"url": URL}}]}


def vt_report(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless,
        "undetected": undetected, "timeout": 0}}}}


class FakeResponse:
    def __init__(self, status=200, data=None, bad_json=False):
        self.status_code, self._data, self._bad = status, data, bad_json

    def json(self):
        if self._bad:
            raise ValueError("json inválido")
        return self._data


class FakeSession:
    """Sessão falsa: responde por (método, trecho da URL), em fila, e registra as chamadas."""

    def __init__(self, routes):
        self.routes = {k: list(v) for k, v in routes.items()}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for (m, fragment), queue in self.routes.items():
            if m == method and fragment in url:
                item = queue.pop(0) if len(queue) > 1 else queue[0]
                if isinstance(item, Exception):
                    raise item
                return item
        raise AssertionError(f"chamada inesperada: {method} {url}")


def run(gsb_resp, vt_resp, threshold=sl.DEFAULT_THRESHOLD):
    """Consulta as duas fontes (simuladas) e classifica."""
    session = FakeSession({("POST", "safebrowsing"): [gsb_resp],
                           ("GET", "/urls/"): [vt_resp]})
    gsb = sl.query_google(URL, "chave-gsb", session)
    vt = sl.query_virustotal(URL, "chave-vt", session, sleep=lambda s: None)
    return sl.classify(gsb, vt, threshold), gsb, vt


class ClassificacaoTests(unittest.TestCase):
    def test_seguro_quando_as_duas_fontes_nao_detectam(self):
        v, _, _ = run(FakeResponse(200, GSB_CLEAN), FakeResponse(200, vt_report()))
        self.assertEqual(v.category, sl.SEGURO)
        self.assertFalse(v.divergence)

    def test_malicioso_so_pelo_google(self):
        v, _, _ = run(FakeResponse(200, GSB_HIT), FakeResponse(200, vt_report()))
        self.assertEqual(v.category, sl.MALICIOSO)
        self.assertTrue(v.divergence)

    def test_malicioso_so_pelo_virustotal(self):
        v, _, _ = run(FakeResponse(200, GSB_CLEAN), FakeResponse(200, vt_report(malicious=5)))
        self.assertEqual(v.category, sl.MALICIOSO)
        self.assertTrue(v.divergence)

    def test_malicioso_quando_as_duas_concordam(self):
        v, _, _ = run(FakeResponse(200, GSB_HIT), FakeResponse(200, vt_report(malicious=12)))
        self.assertEqual(v.category, sl.MALICIOSO)
        self.assertFalse(v.divergence)

    def test_suspeito_com_um_motor_malicioso(self):
        v, _, _ = run(FakeResponse(200, GSB_CLEAN), FakeResponse(200, vt_report(malicious=1)))
        self.assertEqual(v.category, sl.SUSPEITO)

    def test_suspeito_apenas_com_motores_suspicious(self):
        v, _, _ = run(FakeResponse(200, GSB_CLEAN), FakeResponse(200, vt_report(suspicious=2)))
        self.assertEqual(v.category, sl.SUSPEITO)

    def test_limiar_padrao_2_e_suspeito_3_e_malicioso(self):
        v2, _, _ = run(FakeResponse(200, GSB_CLEAN), FakeResponse(200, vt_report(malicious=2)))
        v3, _, _ = run(FakeResponse(200, GSB_CLEAN), FakeResponse(200, vt_report(malicious=3)))
        self.assertEqual(v2.category, sl.SUSPEITO)
        self.assertEqual(v3.category, sl.MALICIOSO)

    def test_limiar_configuravel(self):
        v, _, _ = run(FakeResponse(200, GSB_CLEAN), FakeResponse(200, vt_report(malicious=2)), threshold=2)
        self.assertEqual(v.category, sl.MALICIOSO)


class FalhasDeFonteTests(unittest.TestCase):
    def test_nunca_seguro_se_o_google_falha(self):
        v, gsb, _ = run(FakeResponse(500), FakeResponse(200, vt_report()))
        self.assertFalse(gsb.ok)
        self.assertEqual(v.category, sl.INCONCLUSIVO)

    def test_nunca_seguro_se_o_virustotal_falha(self):
        v, _, vt = run(FakeResponse(200, GSB_CLEAN), FakeResponse(429))
        self.assertIn("cota", vt.error)
        self.assertEqual(v.category, sl.INCONCLUSIVO)

    def test_ameaca_prevalece_mesmo_com_a_outra_fonte_fora(self):
        v, _, _ = run(FakeResponse(200, GSB_HIT), FakeResponse(500))
        self.assertEqual(v.category, sl.MALICIOSO)

    def test_chave_ausente_e_tratada_como_fonte_indisponivel(self):
        session = FakeSession({})
        gsb = sl.query_google(URL, None, session)
        vt = sl.query_virustotal(URL, None, session)
        self.assertFalse(gsb.ok)
        self.assertFalse(vt.ok)
        self.assertEqual(session.calls, [])  # sem chave, nem tenta a rede
        self.assertEqual(sl.classify(gsb, vt).category, sl.INCONCLUSIVO)

    def test_json_invalido_nao_derruba_o_programa(self):
        v, gsb, _ = run(FakeResponse(200, bad_json=True), FakeResponse(200, vt_report()))
        self.assertFalse(gsb.ok)
        self.assertEqual(v.category, sl.INCONCLUSIVO)

    def test_chave_nao_vaza_em_erro_de_rede(self):
        erro = requests.ConnectionError("falha em https://x/?key=SEGREDO123")
        session = FakeSession({("POST", "safebrowsing"): [erro]})
        gsb = sl.query_google(URL, "SEGREDO123", session)
        self.assertFalse(gsb.ok)
        self.assertNotIn("SEGREDO123", gsb.error)

    def test_virustotal_sem_motores_e_inconclusivo(self):
        vt = sl.query_virustotal(URL, "k", FakeSession({("GET", "/urls/"): [FakeResponse(200, vt_report(0, 0, 0, 0))]}))
        self.assertFalse(vt.ok)


class VirusTotalEnvioTests(unittest.TestCase):
    def test_url_desconhecida_e_enviada_e_consultada_ate_concluir(self):
        session = FakeSession({
            ("GET", "/urls/"): [FakeResponse(404)],
            ("POST", "/urls"): [FakeResponse(200, {"data": {"id": "an-123"}})],
            ("GET", "/analyses/an-123"): [
                FakeResponse(200, {"data": {"attributes": {"status": "queued", "stats": {}}}}),
                FakeResponse(200, {"data": {"attributes": {"status": "completed", "stats": {
                    "malicious": 4, "suspicious": 0, "harmless": 55, "undetected": 11}}}}),
            ],
        })
        pausas = []
        vt = sl.query_virustotal(URL, "k", session, sleep=pausas.append)
        self.assertTrue(vt.ok)
        self.assertEqual(vt.malicious, 4)
        # pausa antes do envio e antes de cada uma das 2 consultas da análise
        self.assertEqual(pausas, [sl.POLL_INTERVAL] * 3)

    def test_analise_que_nao_conclui_vira_erro(self):
        pendente = FakeResponse(200, {"data": {"attributes": {"status": "queued", "stats": {}}}})
        session = FakeSession({
            ("GET", "/urls/"): [FakeResponse(404)],
            ("POST", "/urls"): [FakeResponse(200, {"data": {"id": "an-9"}})],
            ("GET", "/analyses/an-9"): [pendente],
        })
        vt = sl.query_virustotal(URL, "k", session, poll_attempts=3, sleep=lambda s: None)
        self.assertFalse(vt.ok)
        self.assertIn("tempo de espera", vt.error)

    def test_identificador_de_url_do_virustotal(self):
        uid = sl.vt_url_id("http://www.example.com/")
        self.assertNotIn("=", uid)
        decodificado = base64.urlsafe_b64decode(uid + "=" * (-len(uid) % 4)).decode()
        self.assertEqual(decodificado, "http://www.example.com/")


class CLITests(unittest.TestCase):
    def _main(self, argv, session=None, env=None):
        saida = io.StringIO()
        env = {"GSB_API_KEY": "g", "VT_API_KEY": "v"} if env is None else env
        codigo = sl.main(argv, session=session, env=env,
                         sleep=lambda s: None, stream=saida)
        return codigo, saida.getvalue()

    def _sessao(self, gsb, vt):
        return FakeSession({("POST", "safebrowsing"): [FakeResponse(200, gsb)],
                            ("GET", "/urls/"): [FakeResponse(200, vt)]})

    def test_codigos_de_saida(self):
        casos = [(GSB_CLEAN, vt_report(), 0), (GSB_CLEAN, vt_report(malicious=1), 1),
                 (GSB_HIT, vt_report(), 2)]
        for gsb, vt, esperado in casos:
            codigo, _ = self._main([URL, "--no-color"], self._sessao(gsb, vt))
            self.assertEqual(codigo, esperado)

    def test_saida_json(self):
        codigo, texto = self._main([URL, "--json"], self._sessao(GSB_HIT, vt_report(malicious=7)))
        dados = json.loads(texto)
        self.assertEqual(codigo, 2)
        self.assertEqual(dados["veredito"], "MALICIOSO")
        self.assertEqual(dados["virustotal"]["malicioso"], 7)
        self.assertEqual(dados["google"]["ameacas"], ["SOCIAL_ENGINEERING"])

    def test_url_sem_esquema_e_rejeitada(self):
        codigo, _ = self._main(["exemplo.test/login"])
        self.assertEqual(codigo, sl.EXIT_USAGE)

    def test_sem_nenhuma_chave_e_erro_de_uso(self):
        codigo, _ = self._main([URL], env={})
        self.assertEqual(codigo, sl.EXIT_USAGE)

    def test_limiar_invalido_e_rejeitado(self):
        codigo, _ = self._main([URL, "--threshold", "0"])
        self.assertEqual(codigo, sl.EXIT_USAGE)

    def test_relatorio_textual_traz_o_veredito(self):
        _, texto = self._main([URL, "--no-color"], self._sessao(GSB_CLEAN, vt_report()))
        self.assertIn("Veredito: SEGURO", texto)


if __name__ == "__main__":
    unittest.main()
