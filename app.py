import os
import hmac
import hashlib
import logging
from flask import Flask, request, abort, jsonify
import requests
from dotenv import load_dotenv

load_dotenv()
EB_API_KEY       = os.environ['EB_API_KEY']
EB_WEBHOOK_SECRET = os.environ['EB_WEBHOOK_SECRET']
EB_BASE_URL     = os.environ.get('EB_BASE_URL', 'https://send.hyperke.com/api')

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    # simple HMAC-SHA256 over payload
    computed = hmac.new(
        EB_WEBHOOK_SECRET.encode(),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature_header)

def get_lead_id_by_email(email: str) -> int:
    # assumes EmailBison supports filtering leads by email
    resp = requests.get(
        f"{EB_BASE_URL}/leads",
        params={"email": email},
        headers={"Authorization": f"Bearer {EB_API_KEY}"}
    )
    resp.raise_for_status()
    items = resp.json().get("data", [])
    if not items:
        raise ValueError(f"No lead found for email {email}")
    return items[0]["id"]

def fetch_scheduled_emails(lead_id: int) -> list[int]:
    resp = requests.get(
        f"{EB_BASE_URL}/leads/{lead_id}/sent-emails",
        params={"scheduledEmails": 1},
        headers={"Authorization": f"Bearer {EB_API_KEY}"}
    )
    resp.raise_for_status()
    return [e["id"] for e in resp.json().get("data", [])]

def attach_email_to_reply(reply_id: int, scheduled_email_id: int):
    resp = requests.post(
        f"{EB_BASE_URL}/replies/{reply_id}/attach-email-to-reply",
        json={"scheduled_email_id": scheduled_email_id},
        headers={"Authorization": f"Bearer {EB_API_KEY}", "Content-Type": "application/json"}
    )
    resp.raise_for_status()
    return resp.json()

@app.route('/webhooks/emailbison/untracked-reply', methods=['POST'])
def handle_untracked_reply():
    sig = request.headers.get('X-EB-Signature', '')
    raw = request.get_data()
    if not verify_signature(raw, sig):
        logging.warning("Invalid signature")
        abort(400, "Invalid signature")

    payload = request.json
    reply_id = payload.get("reply_id")
    lead = payload.get("lead", {})
    if not (reply_id and lead):
        logging.error("Missing reply_id or lead in payload")
        abort(400, "Invalid payload")

    # find lead_id (payload may include it directly)
    lead_id = lead.get("id")
    if not lead_id:
        lead_email = lead.get("email")
        lead_id = get_lead_id_by_email(lead_email)

    # fetch & attach ALL scheduled emails
    scheduled_ids = fetch_scheduled_emails(lead_id)
    results = []
    for sid in scheduled_ids:
        try:
            res = attach_email_to_reply(reply_id, sid)
            results.append({"scheduled_email_id": sid, "status": "attached"})
        except Exception as e:
            logging.exception(f"Failed to attach {sid}")
            results.append({"scheduled_email_id": sid, "status": f"error: {e}"})

    return jsonify({"reply_id": reply_id, "results": results}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
