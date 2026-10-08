import base64
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from google.auth.transport import requests as google_requests
from google.cloud import firestore  # type: ignore[import-untyped,attr-defined]
from google.oauth2 import id_token
from pydantic import BaseModel, Field, model_validator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Orchestra API")


# =====================================================================
# Security & IP Range Validation (Ported from orchestrator_core/gateway.py)
# =====================================================================

DEFAULT_ALLOWED_IPS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    # SendGrid IPs
    "167.89.0.0/17",
    "208.117.48.0/20",
    "50.31.32.0/19",
    "198.37.144.0/20",
    "198.21.0.0/21",
    "192.254.112.0/20",
    "168.245.0.0/17",
    "149.72.0.0/16",
    "159.183.0.0/16",
    # Localhost for testing
    "127.0.0.1",
]


def get_allowed_ips() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Retrieve allowed IPs, parsing from JSON env var or using defaults."""
    env_ips_json = os.environ.get("ALLOWED_IPS_JSON")
    ips = DEFAULT_ALLOWED_IPS
    if env_ips_json:
        try:
            parsed_ips = json.loads(env_ips_json)
            if isinstance(parsed_ips, list):
                ips = parsed_ips
            else:
                logger.warning("ALLOWED_IPS_JSON is not a list. Using defaults.")
        except json.JSONDecodeError:
            logger.error("Failed to parse ALLOWED_IPS_JSON. Using defaults.")

    networks = []
    for ip_str in ips:
        try:
            networks.append(ipaddress.ip_network(ip_str, strict=False))
        except ValueError:
            logger.warning(f"Invalid IP/CIDR string in allowed IPs: {ip_str}")
    return networks


ALLOWED_NETWORKS = get_allowed_ips()


def is_ip_allowed(client_ip: str) -> bool:
    """Check if the client IP is in the allowed networks."""
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    return any(ip_obj in network for network in ALLOWED_NETWORKS)


# =====================================================================
# Decision Models & Exceptions (Ported from orchestrator_core)
# =====================================================================

class WebhookSecurityError(Exception):
    """Raised when a webhook security check fails (HMAC, DKIM, sender)."""


class DecisionAction(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    FEEDBACK_RETRY = "FEEDBACK_RETRY"
    SAGA_ROLLBACK = "SAGA_ROLLBACK"


class ParsedDecision(BaseModel):
    action: DecisionAction
    feedback: str
    target_stage: str | None = None
    raw_text: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DecisionParser:
    @staticmethod
    def parse_reply_text(raw_reply: str) -> ParsedDecision:
        text = raw_reply.strip()

        approve_pattern = re.compile(
            r"\b(approve|approved|ok|yes|lgtm|confirm|accept)\b", re.IGNORECASE
        )
        reject_pattern = re.compile(r"\b(reject|rejected|no|cancel|decline|stop)\b", re.IGNORECASE)
        rollback_pattern = re.compile(r"\b(rollback|revert|undo|abort)\b", re.IGNORECASE)

        if rollback_pattern.search(text):
            action = DecisionAction.SAGA_ROLLBACK
        elif reject_pattern.search(text):
            action = DecisionAction.REJECT
        elif approve_pattern.search(text):
            action = DecisionAction.APPROVE
        else:
            action = DecisionAction.FEEDBACK_RETRY

        return ParsedDecision(
            action=action,
            feedback=text,
            raw_text=raw_reply,
            timestamp=datetime.now(timezone.utc),
        )


class ConductorDecision(BaseModel):
    action: Literal["APPROVE", "REJECT", "FEEDBACK_RETRY", "SAGA_ROLLBACK"]
    feedback_text: str | None = Field(default=None, max_length=2000)
    thread_id: str = Field(min_length=1)
    checkpoint_id: str = Field(min_length=1)

    model_config = {"frozen": True}

    @model_validator(mode="after")
    def validate_feedback_text(self):
        if self.action == "FEEDBACK_RETRY" and not self.feedback_text:
            raise ValueError("feedback_text must be provided when action is FEEDBACK_RETRY")
        return self


# =====================================================================
# Webhook Parsing & Processing (Ported from gateway.py & email_listener.py)
# =====================================================================

def parse_sendgrid_webhook(raw_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Parses a SendGrid Inbound Parse webhook payload into the format expected by process_inbound_webhook.
    """
    headers: dict[str, str] = {}

    raw_headers = raw_payload.get("headers", "")
    for line in raw_headers.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    payload = {
        "dkim_verified": "dkim" in raw_payload,
        "sender": "",
        "text_body": raw_payload.get("text", ""),
    }

    try:
        envelope_val = raw_payload.get("envelope", "{}")
        if isinstance(envelope_val, dict):
            envelope = envelope_val
        else:
            envelope = json.loads(envelope_val)
        payload["sender"] = envelope.get("from", "")
    except (json.JSONDecodeError, TypeError):
        from_field = raw_payload.get("from", "")
        if "<" in from_field and ">" in from_field:
            payload["sender"] = from_field.split("<")[1].split(">")[0]
        else:
            payload["sender"] = from_field

    if not payload["dkim_verified"] and raw_payload.get("dkim_verified"):
        payload["dkim_verified"] = raw_payload.get("dkim_verified")

    if "dkim_verified" in raw_payload and isinstance(raw_payload["dkim_verified"], bool):
        payload["dkim_verified"] = raw_payload["dkim_verified"]

    return payload, headers


def process_inbound_webhook(payload: dict, headers: dict) -> ConductorDecision:
    """
    Processes an incoming email webhook payload.
    Extracts security tokens from headers, validates signatures and sender,
    and returns a mapped ConductorDecision.
    """
    hmac_secret = os.environ.get("ORCHESTRA_HMAC_SECRET", "")
    authorized_email = os.environ.get("CONDUCTOR_AUTHORIZED_EMAIL", "")

    # 1. Sender Verification
    if not payload.get("dkim_verified", False):
        raise WebhookSecurityError("DKIM verification failed.")

    sender = payload.get("sender", "")
    if sender != authorized_email:
        raise WebhookSecurityError(f"Unauthorized sender: {sender}")

    # 2. Cryptographic Header Extraction
    header_val = headers.get("In-Reply-To") or headers.get("References")
    if not header_val:
        raise WebhookSecurityError("Missing In-Reply-To or References header.")

    # Match format: <hmac_signature.thread_id.checkpoint_id@orchestra.local>
    match = re.search(r"<([^\s<>@]+)@orchestra\.local>", header_val)
    if not match:
        raise WebhookSecurityError("Invalid header token format.")

    token_parts = match.group(1).split(".")
    if len(token_parts) != 3:
        raise WebhookSecurityError("Token does not contain exactly 3 parts.")

    provided_signature, thread_id, checkpoint_id = token_parts

    # 3. HMAC Verification
    message = f"{thread_id}.{checkpoint_id}".encode()
    secret_bytes = hmac_secret.encode("utf-8")
    expected_signature = hmac.new(secret_bytes, message, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_signature, provided_signature):
        raise WebhookSecurityError("HMAC signature validation failed.")

    # 4. Payload Decoupling & Decision Mapping
    text_body = payload.get("text_body", "")
    parsed_decision = DecisionParser.parse_reply_text(text_body)

    feedback_text = None
    if parsed_decision.action == DecisionAction.FEEDBACK_RETRY:
        feedback_text = text_body.strip()
    else:
        feedback_text = parsed_decision.feedback

    return ConductorDecision(
        action=parsed_decision.action.value,
        feedback_text=feedback_text,
        thread_id=thread_id,
        checkpoint_id=checkpoint_id,
    )


# =====================================================================
# Firestore State Store
# =====================================================================

_firestore_client: firestore.Client | None = None


def get_firestore_client() -> firestore.Client:
    global _firestore_client
    if _firestore_client is None:
        _firestore_client = firestore.Client()
    return _firestore_client


def save_decision(decision: ConductorDecision) -> dict[str, Any]:
    db = get_firestore_client()
    doc_id = f"{decision.thread_id}:{decision.checkpoint_id}"
    data = {
        "thread_id": decision.thread_id,
        "checkpoint_id": decision.checkpoint_id,
        "action": decision.action,
        "feedback_text": decision.feedback_text,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "status": "RESOLVED",
    }
    db.collection("decisions").document(doc_id).set(data)
    return data


def get_decision(thread_id: str, checkpoint_id: str) -> dict[str, Any] | None:
    db = get_firestore_client()
    doc_id = f"{thread_id}:{checkpoint_id}"
    doc = db.collection("decisions").document(doc_id).get()
    if doc.exists:
        return doc.to_dict()
    return None


# =====================================================================
# IAM Authentication Verification
# =====================================================================

def verify_iam_caller(request: Request) -> dict[str, Any]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Bearer token required")
    token = auth_header.split(" ", 1)[1].strip()
    try:
        claims = id_token.verify_oauth2_token(token, google_requests.Request())
        return dict(claims)
    except Exception as e:
        logger.warning(f"IAM verification failure: {e}")
        raise HTTPException(status_code=401, detail=f"Unauthorized: Invalid IAM token: {e}")


# =====================================================================
# HTTP Endpoints
# =====================================================================

@app.get("/")
def root():
    return {"service": "orchestra-api", "status": "up"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/v1/webhook/email")
async def email_webhook(request: Request):
    """
    Public SendGrid Inbound Parse webhook receiver.
    Enforces IP filtering, DKIM, and HMAC validation before writing decision to Firestore.
    """
    client_ip = request.client.host if request.client else ""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()

    if not is_ip_allowed(client_ip):
        logger.warning(f"Blocked webhook request from unauthorized IP: {client_ip}")
        raise HTTPException(status_code=403, detail="Forbidden IP")

    try:
        content_type = request.headers.get("Content-Type", "")
        if "application/json" in content_type:
            raw_payload = await request.json()
        elif (
            "multipart/form-data" in content_type
            or "application/x-www-form-urlencoded" in content_type
        ):
            form_data = await request.form()
            raw_payload = dict(form_data)
        else:
            raw_payload = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    try:
        parsed_payload, parsed_headers = parse_sendgrid_webhook(raw_payload)
        decision = process_inbound_webhook(parsed_payload, parsed_headers)
        save_decision(decision)
        return {
            "status": "success",
            "decision": decision.action,
            "thread_id": decision.thread_id,
            "checkpoint_id": decision.checkpoint_id,
        }
    except WebhookSecurityError as e:
        logger.error(f"Security error processing webhook: {e}")
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.exception("Error processing webhook payload")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.get("/v1/decisions/{thread_id}/{checkpoint_id}")
def get_decision_endpoint(thread_id: str, checkpoint_id: str, request: Request):
    """
    IAM-authenticated decision check endpoint.
    Returns {"status": "PENDING"} or {"status": "RESOLVED", "decision": {...}}.
    """
    verify_iam_caller(request)
    record = get_decision(thread_id, checkpoint_id)
    if not record:
        return {"status": "PENDING"}

    return {
        "status": "RESOLVED",
        "decision": {
            "action": record.get("action"),
            "feedback_text": record.get("feedback_text"),
            "thread_id": record.get("thread_id"),
            "checkpoint_id": record.get("checkpoint_id"),
            "resolved_at": record.get("resolved_at"),
        },
    }
