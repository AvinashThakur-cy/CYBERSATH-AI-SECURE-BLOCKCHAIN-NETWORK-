"""Deterministic, offline analyzers used by the security workbench."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


BASE_DIR = Path(__file__).resolve().parent.parent
AUDIT_LOG_PATH = BASE_DIR / "logs" / "audit.log"
AUDIT_LOGGER = logging.getLogger("cybersathi.analysis.audit")


def _configure_audit_logger() -> None:
    if AUDIT_LOGGER.handlers:
        return
    AUDIT_LOGGER.setLevel(logging.INFO)
    AUDIT_LOGGER.propagate = False
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(AUDIT_LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    AUDIT_LOGGER.addHandler(handler)


class URLAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value or any(character.isspace() for character in value):
            raise ValueError("url must be a non-empty URL without whitespace")
        parsed = _parse_url(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("url must include an http or https scheme and hostname")
        return value


class EmailAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        local_part = value.split("@", 1)[0] if "@" in value else ""
        if (
            not value
            or any(character.isspace() for character in value)
            or local_part.startswith(".")
            or local_part.endswith(".")
            or ".." in local_part
            or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value)
        ):
            raise ValueError("email must be a valid address")
        return value


class PasswordAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=256)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("password must not be empty")
        return value


class AnalysisResponse(BaseModel):
    status: str = "ok"
    analysis_type: str
    risk_level: str
    score: int = Field(ge=0, le=100)
    summary: str
    findings: list[str]
    recommendations: list[str]
    metadata: dict[str, str | int | bool]
    analyzed_at: str


def _parse_url(value: str) -> SplitResult:
    try:
        parsed = urlsplit(value)
        # Accessing hostname and port validates malformed bracketed/port hosts.
        _ = parsed.hostname
        _ = parsed.port
        return parsed
    except ValueError as error:
        raise ValueError("url is malformed") from error


def _risk_level(score: int) -> str:
    if score <= 25:
        return "low"
    if score <= 60:
        return "medium"
    return "high"


def _response(
    analysis_type: str,
    score: int,
    summary: str,
    findings: list[str],
    recommendations: list[str],
    metadata: dict[str, str | int | bool],
) -> dict:
    return AnalysisResponse(
        analysis_type=analysis_type,
        risk_level=_risk_level(score),
        score=max(0, min(100, score)),
        summary=summary,
        findings=findings,
        recommendations=recommendations,
        metadata=metadata,
        analyzed_at=datetime.now(UTC).isoformat(),
    ).model_dump()


def analyze_url(value: str) -> dict:
    parsed = _parse_url(value)
    hostname = (parsed.hostname or "").lower()
    score = 0
    findings: list[str] = []
    recommendations: list[str] = []

    if parsed.scheme.lower() != "https":
        score += 25
        findings.append("The URL does not use HTTPS.")
        recommendations.append("Prefer an HTTPS URL before submitting sensitive information.")
    if "@" in parsed.netloc:
        score += 30
        findings.append("The URL contains user-info before the hostname.")
        recommendations.append("Avoid links that hide the destination behind user-info.")
    if hostname.startswith("xn--") or ".xn--" in hostname:
        score += 15
        findings.append("The hostname uses an internationalized punycode label.")
        recommendations.append("Verify the displayed domain carefully for look-alike characters.")
    if len(hostname.split(".")) > 4:
        score += 10
        findings.append("The hostname has an unusually deep subdomain chain.")
    if any(term in hostname for term in ("login", "verify", "wallet", "account", "secure-update")):
        score += 15
        findings.append("The hostname contains a commonly impersonated account or security term.")
        recommendations.append("Navigate to the service directly instead of following the link.")
    if any(term in parsed.path.lower() for term in ("/login", "/verify", "/reset", "/wallet")):
        score += 15
        findings.append("The path requests a sensitive account or wallet operation.")
        recommendations.append("Confirm the destination independently before entering credentials.")
    if parsed.port not in (None, 80, 443):
        score += 10
        findings.append("The URL uses a non-standard port.")
        recommendations.append("Confirm the port is expected for the service.")
    if not findings:
        findings.append("No high-risk URL patterns were detected by local rules.")
        recommendations.append("Still confirm the domain and page context before trusting it.")

    return _response(
        "url",
        score,
        "The URL was checked with deterministic local syntax and hostname rules.",
        findings,
        recommendations,
        {
            "scheme": parsed.scheme.lower(),
            "hostname": hostname,
            "has_path": bool(parsed.path),
            "has_query": bool(parsed.query),
            "length": len(value),
        },
    )


DISPOSABLE_EMAIL_DOMAINS = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com"}


def analyze_email(value: str) -> dict:
    local_part, domain = value.rsplit("@", 1)
    score = 0
    findings: list[str] = []
    recommendations: list[str] = []
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        score += 55
        findings.append("The domain is listed in the local disposable-email set.")
        recommendations.append("Use a monitored, organization-controlled mailbox.")
    if "+" in local_part:
        score += 5
        findings.append("The address uses a plus-tagged alias.")
    if len(local_part) > 64:
        score += 10
        findings.append("The mailbox name is unusually long.")
    if not findings:
        findings.append("The address has a conventional local format and domain.")
        recommendations.append("Confirm ownership with a verification message before granting access.")
    elif not recommendations:
        recommendations.append("Treat the address as unverified until ownership is confirmed.")

    return _response(
        "email",
        score,
        "The email address was checked locally for syntax and known disposable-domain patterns.",
        findings,
        recommendations,
        {"domain": domain, "local_part_length": len(local_part), "length": len(value)},
    )


def analyze_password(value: str) -> dict:
    length = len(value)
    has_upper = bool(re.search(r"[A-Z]", value))
    has_lower = bool(re.search(r"[a-z]", value))
    has_digit = bool(re.search(r"\d", value))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", value))
    variety = sum((has_upper, has_lower, has_digit, has_symbol))
    strength_score = min(100, length * 4 + variety * 8)
    findings: list[str] = []
    recommendations: list[str] = []
    if length < 12:
        findings.append("The password is shorter than the recommended 12 characters.")
        recommendations.append("Use at least 12 characters, preferably with a unique passphrase.")
    if variety < 3:
        findings.append("The password uses too few character categories.")
        recommendations.append("Mix uppercase, lowercase, numbers, and symbols.")
    if re.search(r"(.)\1{2,}", value):
        findings.append("The password contains repeated consecutive characters.")
        recommendations.append("Avoid repeated characters and predictable patterns.")
    if value.lower() in {"password", "password123", "qwerty", "letmein", "admin123"}:
        findings.append("The password matches a commonly guessed value.")
        recommendations.append("Choose a unique password that is not based on a common word.")
        strength_score = min(strength_score, 15)
    if not findings:
        findings.append("The password meets the local length and variety checks.")
        recommendations.append("Never reuse it and store it in a trusted password manager.")

    risk_score = 100 - strength_score
    return _response(
        "password",
        risk_score,
        "The password was evaluated locally; the password itself is never returned or logged.",
        findings,
        recommendations,
        {
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol,
            "character_categories": variety,
            "strength_score": strength_score,
        },
    )


def record_analysis_audit(analysis_type: str, metadata: dict[str, str | int | bool]) -> None:
    """Write only non-sensitive metadata; request values are intentionally excluded."""

    _configure_audit_logger()
    event = {
        "event": "analysis",
        "analysis_type": analysis_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": metadata,
    }
    AUDIT_LOGGER.info(json.dumps(event, sort_keys=True))
