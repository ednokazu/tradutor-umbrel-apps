"""Tradutor de senhas de PDF (Opção A) - Edno AI.

Recebe um PDF e só o NOME do perfil (ex.: "c6"), ou "auto" para tentar todas as senhas. Busca a senha num arquivo
protegido, chama o Stirling PDF (multipart) e devolve o PDF aberto.

Regras de segurança (do plano de 17/10/2026):
- só aceita POST /desbloquear com token no cabeçalho X-Tradutor-Token;
- a senha NUNCA vai em URL, em log nem em resposta;
- o PDF não é gravado em disco nem em log;
- perfil fora da lista permitida: erro curto, sem detalhes.
"""
import hmac
import io
import json
import os
import re

import requests
from flask import Flask, Response, jsonify, request

STIRLING_URL = os.environ["STIRLING_URL"].rstrip("/")  # ex.: http://stirling-pdf_app_1:8080
TOKEN_FILE = os.environ.get("TOKEN_FILE", "/segredos/token")
SENHAS_FILE = os.environ.get("SENHAS_FILE", "/segredos/senhas.json")
PERFIL_OK = re.compile(r"^[a-z0-9_-]{1,32}$")

def _preparar_segredos():
    """Primeira subida: cria a pasta, um token aleatório e uma lista de perfis vazia.
    Nenhuma senha é criada aqui; as senhas só entram quando o Edno as digitar."""
    import secrets
    pasta = os.path.dirname(TOKEN_FILE)
    os.makedirs(pasta, exist_ok=True)
    os.chmod(pasta, 0o700)
    if not os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(32))
    if not os.path.exists(SENHAS_FILE):
        with open(SENHAS_FILE, "w", encoding="utf-8") as f:
            f.write("{}")
    for caminho in (TOKEN_FILE, SENHAS_FILE):
        os.chmod(caminho, 0o600)


_preparar_segredos()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB


def _ler(caminho):
    with open(caminho, "r", encoding="utf-8") as f:
        return f.read()


def erro(codigo, chave):
    # Resposta curta e fixa: nada de detalhes, nada de eco do que foi enviado.
    return jsonify({"erro": chave}), codigo


@app.get("/saude")
def saude():
    return jsonify({"ok": True})


@app.post("/desbloquear")
def desbloquear():
    # 1) token (lido do arquivo a cada chamada: trocar o token não exige rebuild)
    try:
        esperado = _ler(TOKEN_FILE).strip()
    except OSError:
        return erro(500, "indisponivel")
    enviado = request.headers.get("X-Tradutor-Token", "")
    if not esperado or not hmac.compare_digest(enviado.encode(), esperado.encode()):
        return erro(401, "nao_autorizado")

    # 2) perfil: um nome da lista, ou "auto" (tenta todas as senhas cadastradas)
    perfil = request.form.get("perfil", "")
    if not PERFIL_OK.match(perfil):
        return erro(400, "perfil_invalido")
    try:
        senhas = json.loads(_ler(SENHAS_FILE))
    except (OSError, ValueError):
        return erro(500, "indisponivel")
    if perfil == "auto":
        candidatos = [(n, s) for n, s in senhas.items() if isinstance(s, str) and s]
        if not candidatos:
            return erro(404, "perfil_desconhecido")
    else:
        senha = senhas.get(perfil)
        if not isinstance(senha, str) or not senha:
            return erro(404, "perfil_desconhecido")
        candidatos = [(perfil, senha)]
        senha = None

    # 3) arquivo
    arquivo = request.files.get("file")
    if arquivo is None:
        return erro(400, "sem_arquivo")
    conteudo = arquivo.read()
    if not conteudo.startswith(b"%PDF"):
        return erro(400, "nao_e_pdf")

    # 4) Stirling: tenta cada candidato (senha só dentro do corpo multipart, nunca na URL)
    for nome, senha in candidatos:
        try:
            r = requests.post(
                f"{STIRLING_URL}/api/v1/security/remove-password",
                files={"fileInput": ("entrada.pdf", io.BytesIO(conteudo), "application/pdf")},
                data={"password": senha},
                timeout=60,
            )
        except requests.RequestException:
            return erro(502, "stirling_indisponivel")
        finally:
            senha = None  # não manter em variável
        if r.status_code == 200 and r.content.startswith(b"%PDF"):
            resp = Response(r.content, mimetype="application/pdf")
            resp.headers["X-Perfil-Usado"] = nome  # só o NOME do perfil, nunca a senha
            return resp

    # Nenhuma senha abriu: mesma resposta curta, sem repassar o texto do Stirling.
    return erro(422, "nao_foi_possivel_abrir")
