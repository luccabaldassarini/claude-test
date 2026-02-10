import hashlib
import hmac
import json
import os
from pathlib import Path

import resend
from dotenv import load_dotenv
from flask import Flask, abort, request

load_dotenv()

# ======= CONFIG =======
RESEND_API_KEY = os.environ["RESEND_API_KEY"]
TALLY_SIGNING_SECRET = os.environ.get("TALLY_SIGNING_SECRET", "")
EMAIL_FROM = "notas+spark@coeh.co"
EMAIL_SUBJECT = "Documento recepcionado com sucesso"

resend.api_key = RESEND_API_KEY

app = Flask(__name__)

TEMPLATE_PATH = Path(__file__).parent / "templates" / "email_confirmacao.html"


def verify_tally_signature(payload_body: bytes, signature: str) -> bool:
    """Verifica a assinatura do webhook do Tally para garantir autenticidade."""
    if not TALLY_SIGNING_SECRET:
        return True  # pula verificacao se o secret nao estiver configurado
    computed = hmac.new(
        TALLY_SIGNING_SECRET.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def extract_field(fields: list[dict], label: str) -> str | None:
    """Extrai o valor de um campo do Tally pelo label."""
    for field in fields:
        if field.get("label", "").strip().lower() == label.strip().lower():
            value = field.get("value")
            if isinstance(value, str):
                return value.strip()
            return value
    return None


def render_template(supplier_name: str) -> str:
    """Carrega e renderiza o template HTML do email."""
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    html = html.replace("{{supplier_name}}", supplier_name)
    return html


def send_email(to_email: str, supplier_name: str) -> dict:
    """Envia o email de confirmacao via Resend."""
    html_content = render_template(supplier_name)
    params = {
        "from_": EMAIL_FROM,
        "to": [to_email],
        "subject": EMAIL_SUBJECT,
        "html": html_content,
    }
    return resend.Emails.send(params)


@app.route("/webhook/tally", methods=["POST"])
def tally_webhook():
    """Endpoint que recebe webhooks do Tally e envia email de confirmacao."""
    # Verificar assinatura
    signature = request.headers.get("tally-signature", "")
    if not verify_tally_signature(request.get_data(), signature):
        abort(401, "Assinatura invalida")

    payload = request.get_json(silent=True)
    if not payload:
        abort(400, "Payload vazio ou JSON invalido")

    # Extrair campos do formulario Tally
    data = payload.get("data", {})
    fields = data.get("fields", [])

    # Buscar email e nome nos campos do formulario
    supplier_email = extract_field(fields, "Email")
    supplier_name = extract_field(fields, "Nome") or "Fornecedor"

    if not supplier_email:
        abort(400, "Campo 'Email' nao encontrado no formulario")

    # Enviar email via Resend
    result = send_email(supplier_email, supplier_name)
    app.logger.info("Email enviado para %s – Resend ID: %s", supplier_email, result.get("id"))

    return {"status": "ok", "resend_id": result.get("id")}, 200


@app.route("/health", methods=["GET"])
def health():
    return {"status": "healthy"}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
