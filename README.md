# SafeLink CLI

Ferramenta de linha de comando em Python que verifica a reputação de uma URL no
**Google Safe Browsing (v4)** e no **VirusTotal (v3)** e devolve um veredito único:
`SEGURO`, `SUSPEITO`, `MALICIOSO` ou `INCONCLUSIVO`.

Projeto acadêmico (Faculdade Impacta de Tecnologia). Uso educacional e pessoal:
as camadas gratuitas das duas APIs **não permitem uso comercial**.

## Como funciona

1. Você informa uma URL.
2. O SafeLink consulta o Google Safe Browsing e o VirusTotal.
3. Aplica regras fixas (veja "Vereditos e códigos de saída") e mostra um veredito e o motivo.

## Estrutura do repositório

| Arquivo | Função |
| --- | --- |
| `safelink.py` | Programa principal (consultas às APIs, classificação e linha de comando) |
| `test_safelink.py` | Testes automatizados, sem acesso à internet |
| `requirements.txt` | Dependências (`requests`) |
| `README.md` | Este documento |

## Requisitos

- Python 3 (os testes do projeto foram executados em Python 3.13, em Linux)
- Biblioteca `requests`
- Uma chave de API do Google Safe Browsing e/ou do VirusTotal (gratuitas)

## Instalação

```bash
git clone <URL-DO-REPOSITORIO>
cd <PASTA-DO-REPOSITORIO>

# opcional, recomendado: ambiente virtual
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Em alguns sistemas o comando é `python3` em vez de `python`.

## Chaves de API

As chaves são lidas de variáveis de ambiente. Elas **não** são aceitas como argumento,
para não ficarem no histórico do terminal. Nunca grave as chaves em arquivos do projeto.

```bash
# Linux e macOS
export GSB_API_KEY="sua-chave-google"
export VT_API_KEY="sua-chave-virustotal"
```

```powershell
# Windows (PowerShell)
$env:GSB_API_KEY = "sua-chave-google"
$env:VT_API_KEY = "sua-chave-virustotal"
```

- Google: habilite a *Safe Browsing API* em um projeto do Google Cloud e crie uma chave em Credenciais.
- VirusTotal: crie uma conta gratuita e copie a chave da API no perfil.

## Uso

```bash
python safelink.py "https://exemplo.com/pagina"
python safelink.py "https://exemplo.com/pagina" --json
python safelink.py "https://exemplo.com/pagina" --threshold 2 --no-color
```

| Opção | Efeito |
| --- | --- |
| `--threshold N` | Número de motores do VirusTotal que tornam o veredito `MALICIOSO` (padrão: 3) |
| `--json` | Imprime o resultado em JSON |
| `--no-color` | Desativa as cores ANSI |

A URL deve começar com `http://` ou `https://`.

## Vereditos e códigos de saída

| Veredito | Código | Regra |
| --- | --- | --- |
| `SEGURO` | 0 | As duas fontes responderam e nenhuma sinalizou a URL |
| `SUSPEITO` | 1 | De 1 a (N−1) motores `malicious` no VirusTotal, ou ao menos 1 motor `suspicious` |
| `MALICIOSO` | 2 | O Google lista a URL, ou o VirusTotal tem N ou mais motores `malicious` |
| `INCONCLUSIVO` | 3 | Uma fonte falhou e a outra não encontrou ameaça |
| (erro de uso) | 4 | URL inválida, `--threshold` menor que 1 ou nenhuma chave configurada |

As regras são avaliadas na ordem `MALICIOSO`, `SUSPEITO`, `SEGURO`, `INCONCLUSIVO`.
Quando as fontes divergem, prevalece a que detectou ameaça. Nunca se declara `SEGURO`
com uma das fontes indisponível.

## Testes

```bash
python -m unittest -v test_safelink
```

Os 24 testes usam respostas **simuladas** das APIs. Eles não usam internet nem chaves de API.
Eles validam a lógica de classificação, não o comportamento dos serviços reais nem a taxa
de acerto contra ameaças verdadeiras.

| Grupo | Testes | O que verifica |
| --- | --- | --- |
| Classificação | 8 | Cada veredito (seguro, suspeito, malicioso), a divergência entre fontes e o limiar |
| Falhas de fonte | 7 | Nunca declarar seguro se uma fonte falhar (erro, cota, chave ausente) |
| Envio ao VirusTotal | 3 | URL nova enviada para análise, com pausas que respeitam a cota |
| Linha de comando | 6 | Códigos de saída, saída em JSON e erros de uso |

## Prova de conceito

Os resultados com URLs reais ainda devem ser registrados pelo autor (consulte o artigo).
Não use os testes automatizados como medida de acerto.

## Limitações

- O resultado `SEGURO` significa apenas que nenhuma das duas fontes sinalizou a URL.
- A ferramenta não abre a página nem segue redirecionamentos.
- API pública do VirusTotal: 4 requisições por minuto e 500 por dia. Não há cache.
- O limiar padrão (3 motores) é uma escolha de projeto, não calibrada com dados reais.
- A URL consultada é enviada a serviços de terceiros: não consulte URLs com tokens ou dados pessoais.
