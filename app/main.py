from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from io import BytesIO
from pathlib import Path
from datetime import UTC, datetime
from typing import Any, Literal, cast
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.graphics.shapes import Drawing, Rect, String
from app.analysis import (
    AnalysisResponse,
    EmailAnalysisRequest,
    PasswordAnalysisRequest,
    URLAnalysisRequest,
    analyze_email,
    analyze_password,
    analyze_url,
    record_analysis_audit,
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="CYBERSATHI Blockchain Security Platform",
    version="2.0.0",
    description="Operational security telemetry and response workflows for blockchain infrastructure.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

ActionName = Literal[
    "run-scan",
    "isolate-wallet",
    "freeze-node",
    "escalate-incident",
    "generate-report",
]

class ActionRequest(BaseModel):
    action: ActionName
    target: str | None = Field(default=None, max_length=120)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=500)

def now_iso() -> str:
    return datetime.now(UTC).isoformat()

def build_dashboard() -> dict:
    return {
        "generated_at": now_iso(),
        "summary": {
            "threat_level": "High",
            "security_score": 88,
            "blockchain_health": 94,
            "prediction_confidence": 91,
            "trust_score": 93,
            "system_integrity": 96,
            "live_nodes": 18,
            "active_incidents": 3,
            "monitored_wallets": 284,
            "flagged_wallets": 7,
        },
        "executive_brief": "CYBERSATHI detected elevated bridge activity and a validator rotation anomaly. No confirmed asset loss is present; operator approval is required before containment changes are applied.",
        "risk_trend": {
            "labels": ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
            "values": [42, 48, 39, 58, 72, 67],
        },
        "signals": [
            {"name": "Wallet velocity anomaly", "score": 82, "detail": "7 wallets crossed the configured transfer threshold."},
            {"name": "Cross-chain bridge drift", "score": 76, "detail": "Bridge-04 has an unusual signing sequence."},
            {"name": "Validator rotation", "score": 69, "detail": "Rotation occurred outside the approved change window."},
            {"name": "Keystore access pattern", "score": 54, "detail": "Access volume is elevated but not confirmed malicious."},
        ],
        "nodes": [
            {"name": "Validator-01", "role": "Consensus", "health": 98, "status": "Online", "latency": "42 ms"},
            {"name": "Validator-02", "role": "Consensus", "health": 96, "status": "Online", "latency": "49 ms"},
            {"name": "Gateway-03", "role": "RPC Gateway", "health": 86, "status": "Degraded", "latency": "118 ms"},
            {"name": "Bridge-04", "role": "Bridge Relayer", "health": 61, "status": "Review", "latency": "204 ms"},
        ],
        "incidents": [
            {"id": "INC-2048", "severity": "High", "title": "Suspicious validator rotation", "owner": "Unassigned", "age": "12 min"},
            {"id": "INC-2047", "severity": "Medium", "title": "Rogue bridge contract activity", "owner": "A. Rao", "age": "38 min"},
            {"id": "INC-2046", "severity": "Low", "title": "Unusual keystore access pattern", "owner": "S. Mehta", "age": "1 hr"},
        ],
        "attribution": {
            "status": "Unconfirmed",
            "source": "Internal telemetry only",
            "source_indicators": ["Bridge-04 signing sequence", "Validator rotation outside approved window"],
            "ip_address": None,
            "note": "No verified attacker IP is available. Infrastructure signals do not prove identity or attribution.",
        },
    }

MODULES = {
    "threat-intelligence": {"label": "Threat Intelligence", "eyebrow": "Detect", "description": "Review explainable signals, confidence, and recent blockchain risk movement.", "metrics": ["prediction_confidence", "flagged_wallets"], "actions": ["run-scan", "generate-report"]},
    "attack-investigation": {"label": "Attack Investigation", "eyebrow": "Investigate", "description": "Trace the highest-priority incident from signal to recommended containment.", "metrics": ["active_incidents", "system_integrity"], "actions": ["escalate-incident", "freeze-node"]},
    "blockchain-explorer": {"label": "Blockchain Explorer", "eyebrow": "Observe", "description": "Inspect chain health, bridge reliability, and infrastructure latency from one view.", "metrics": ["blockchain_health", "live_nodes"], "actions": ["run-scan", "generate-report"]},
    "node-management": {"label": "Node Management", "eyebrow": "Operate", "description": "Review validator health and prepare controlled, operator-approved node actions.", "metrics": ["live_nodes", "system_integrity"], "actions": ["freeze-node", "generate-report"]},
    "wallet-intelligence": {"label": "Wallet Intelligence", "eyebrow": "Trace", "description": "Monitor wallet velocity, flagged addresses, and suspicious transaction behavior.", "metrics": ["monitored_wallets", "flagged_wallets"], "actions": ["isolate-wallet", "generate-report"]},
    "incident-response": {"label": "Incident Response", "eyebrow": "Respond", "description": "Coordinate escalation and containment while preserving an auditable response trail.", "metrics": ["active_incidents", "security_score"], "actions": ["escalate-incident", "generate-report"]},
    "attack-dna": {"label": "Attack DNA", "eyebrow": "Correlate", "description": "Compare behavior fingerprints across wallet, bridge, and validator activity.", "metrics": ["prediction_confidence", "security_score"], "actions": ["run-scan", "generate-report"]},
    "ai-copilot": {"label": "AI Copilot", "eyebrow": "Assist", "description": "Turn current telemetry into a clear containment recommendation for the operator.", "metrics": ["trust_score", "prediction_confidence"], "actions": ["escalate-incident", "generate-report"]},
}

ACTION_RESULTS = {
    "run-scan": ("Integrity scan completed", "Chain, wallet, and node checks completed against the current telemetry snapshot."),
    "isolate-wallet": ("Wallet isolation prepared", "Outgoing activity for the selected wallet group is marked for operator approval."),
    "freeze-node": ("Node freeze prepared", "The affected infrastructure is staged for controlled isolation."),
    "escalate-incident": ("Incident escalated", "INC-2048 has been assigned priority response status."),
    "generate-report": ("Report prepared", "The latest findings and recommended controls are ready to export."),
}


@app.get("/", response_class=HTMLResponse)
async def read_root() -> HTMLResponse:
    return HTMLResponse((BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8"))

@app.get("/api/dashboard")
async def dashboard() -> dict:
    return build_dashboard()


@app.get("/api/health")
async def health() -> dict:
    return {
        "status": "ok",
        "backend": "running",
        "analysis_engine": "ready",
        "service": "cybersathi",
        "version": app.version,
    }


@app.post("/api/analyze/url", response_model=AnalysisResponse)
@app.post("/api/analyze-url", response_model=AnalysisResponse, include_in_schema=False)
async def analyze_url_endpoint(request: URLAnalysisRequest) -> dict:
    result = analyze_url(request.url)
    record_analysis_audit("url", result["metadata"])
    return result


@app.post("/api/analyze/email", response_model=AnalysisResponse)
@app.post("/api/analyze-email", response_model=AnalysisResponse, include_in_schema=False)
async def analyze_email_endpoint(request: EmailAnalysisRequest) -> dict:
    result = analyze_email(request.email)
    record_analysis_audit("email", result["metadata"])
    return result


@app.post("/api/analyze/password", response_model=AnalysisResponse)
@app.post("/api/analyze-password", response_model=AnalysisResponse, include_in_schema=False)
async def analyze_password_endpoint(request: PasswordAnalysisRequest) -> dict:
    result = analyze_password(request.password)
    record_analysis_audit("password", result["metadata"])
    return result


@app.get("/api/telemetry")
async def telemetry() -> dict:
    data = build_dashboard()
    data["threat_level"] = data["summary"]["threat_level"]
    data.update(data["summary"])
    data["timeline"] = [{"label": label, "value": value} for label, value in zip(data["risk_trend"]["labels"], data["risk_trend"]["values"])]
    data["explainability"] = [{"reason": item["name"], "weight": item["score"] / 100} for item in data["signals"]]
    data["node_health"] = [{"name": node["name"], "health": node["health"], "status": node["status"].lower()} for node in data["nodes"]]
    data["incident_queue"] = [{"id": item["id"], "severity": item["severity"], "summary": item["title"]} for item in data["incidents"]]
    data["attack_investigation"] = {"priority": data["incidents"][0]["title"], "confidence": data["summary"]["prediction_confidence"], "recommendation": "Review the validator change window and bridge signing permissions."}
    data["wallet_intelligence"] = {"monitored_wallets": data["summary"]["monitored_wallets"], "flagged_wallets": data["summary"]["flagged_wallets"], "top_signal": data["signals"][0]["name"]}
    return data

@app.get("/api/modules/{module_id}")
async def module_details(module_id: str) -> dict:
    module = MODULES.get(module_id)
    if module is None:
        raise HTTPException(status_code=404, detail="Module not found")
    dashboard_data = build_dashboard()
    return {"module": module, "metrics": {key: dashboard_data["summary"][key] for key in module["metrics"]}, "signals": dashboard_data["signals"][:3]}

@app.post("/api/actions")
async def run_action(request: ActionRequest) -> dict:
    title, detail = ACTION_RESULTS[request.action]
    response: dict[str, object] = {"status": "accepted", "action": request.action, "target": request.target or "current workspace", "title": title, "detail": detail, "timestamp": now_iso()}
    if request.action == "run-scan":
        dashboard_data = build_dashboard()
        nodes = dashboard_data["nodes"]
        response["scan"] = {
            "status": "completed",
            "security_score": dashboard_data["summary"]["security_score"],
            "blockchain_health": dashboard_data["summary"]["blockchain_health"],
            "nodes_checked": len(nodes),
            "wallets_checked": dashboard_data["summary"]["monitored_wallets"],
            "findings": sum(1 for node in nodes if node["health"] < 90),
            "finding_summary": "Bridge-04 requires review; all other monitored nodes are within operating thresholds.",
        }
    return response


@app.api_route("/api/actions/{action_name}", methods=["GET", "POST"])
async def legacy_action(action_name: str) -> dict:
    if action_name not in ACTION_RESULTS:
        raise HTTPException(status_code=404, detail="Unknown action")
    return await run_action(ActionRequest(action=cast(ActionName, action_name)))

@app.get("/api/report")
async def security_report() -> dict:
    data = build_dashboard()
    return {
        "report_name": "CYBERSATHI Blockchain Security Report",
        "generated_at": now_iso(),
        "risk_level": data["summary"]["threat_level"],
        "overall_score": data["summary"]["security_score"],
        "executive_brief": data["executive_brief"],
        "findings": [signal["detail"] for signal in data["signals"]],
        "recommended_controls": [
            "Require multi-party approval for validator and bridge changes.",
            "Keep wallet velocity thresholds enabled across monitored chains.",
            "Archive incident evidence before closing containment actions.",
        ],
    }


@app.get("/api/report.pdf")
async def security_report_pdf() -> StreamingResponse:
    data = build_dashboard()
    summary = data["summary"]
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CyberSathiTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, textColor=colors.HexColor("#17352b"), spaceAfter=6)
    body_style = ParagraphStyle("CyberSathiBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=colors.HexColor("#30453d"))
    small_style = ParagraphStyle("CyberSathiSmall", parent=body_style, fontSize=8, leading=10)
    story = [Paragraph("CYBERSATHI", title_style), Paragraph("Blockchain Security Operations Report", styles["Heading2"]), Paragraph(f"Generated {data['generated_at']}", small_style), Spacer(1, 8)]
    story.append(Paragraph("Executive assessment", styles["Heading2"]))
    story.append(Paragraph(data["executive_brief"], body_style))
    story.append(Spacer(1, 10))

    score_data = [["Security score", "Blockchain health", "Model confidence", "Threat posture"], [f"{summary['security_score']}/100", f"{summary['blockchain_health']}%", f"{summary['prediction_confidence']}%", summary["threat_level"]]]
    score_table = Table(score_data, colWidths=[42 * mm] * 4)
    score_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dff4cf")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17352b")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#b9cec0")), ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(score_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Risk movement", styles["Heading2"]))
    chart = Drawing(470, 125)
    values = data["risk_trend"]["values"]
    for index, value in enumerate(values):
        x = 18 + index * 72
        fill_color: Any = colors.HexColor("#8dcc62")
        stroke_color: Any = colors.HexColor("#5c9845")
        chart.add(Rect(x, 25, 32, value, fillColor=fill_color, strokeColor=stroke_color))
        chart.add(String(x + 5, 8, data["risk_trend"]["labels"][index], fontSize=7, fillColor=colors.HexColor("#52675d")))
        chart.add(String(x + 9, 30 + value, str(value), fontSize=7, fillColor=colors.HexColor("#17352b")))
    story.append(chart)
    story.append(Spacer(1, 4))

    story.append(Paragraph("Explainable findings", styles["Heading2"]))
    signal_rows = [["Signal", "Score", "Evidence"]] + [[signal["name"], f"{signal['score']}%", signal["detail"]] for signal in data["signals"]]
    signal_table = Table(signal_rows, colWidths=[48 * mm, 18 * mm, 108 * mm], repeatRows=1)
    signal_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17352b")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#c8d6ce")), ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f7f2")]), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(signal_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Infrastructure and response queue", styles["Heading2"]))
    node_rows = [["Node", "Role", "Health", "Status", "Latency"]] + [[node["name"], node["role"], f"{node['health']}%", node["status"], node["latency"]] for node in data["nodes"]]
    node_table = Table(node_rows, colWidths=[32 * mm, 38 * mm, 20 * mm, 28 * mm, 25 * mm], repeatRows=1)
    node_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17352b")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#c8d6ce")), ("FONTSIZE", (0, 0), (-1, -1), 8), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f7f2")])]))
    story.append(node_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("Incidents: " + "; ".join(f"{item['id']} ({item['severity']}) {item['title']}" for item in data["incidents"]), body_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Attribution status", styles["Heading2"]))
    story.append(Paragraph(data["attribution"]["note"], body_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Recommended controls", styles["Heading2"]))
    story.append(Paragraph("<br/>".join(f"• {control}" for control in (await security_report())["recommended_controls"]), body_style))
    document.build(story)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=cybersathi-security-report.pdf"})


@app.post("/api/chat")
async def shravi_chat(request: ChatRequest) -> dict:
    message = request.message.lower()
    data = build_dashboard()
    if any(word in message for word in ["ip", "attacker", "hacker", "identify", "attribution"]):
        intent = "Attribution guidance"
        confidence = "High"
        answer = "I cannot confirm a hacker IP from this telemetry. Current evidence points to Bridge-04 signing drift and an unapproved validator rotation, but that does not prove identity. Check reverse-proxy, node, RPC, firewall, and exchange logs before making an attribution claim."
        evidence = ["Bridge-04 signing sequence is abnormal", "Validator rotation occurred outside the approved window", "No verified source IP exists in the current snapshot"]
        next_steps = ["Collect reverse-proxy and RPC access logs", "Correlate firewall and node timestamps", "Preserve evidence before attributing an actor"]
        suggested_action = None
    elif any(word in message for word in ["scan", "score", "health", "status"]):
        intent = "Current security posture"
        confidence = "High"
        answer = f"The latest verified snapshot is {data['summary']['security_score']}/100 security, {data['summary']['blockchain_health']}% blockchain health, and {data['summary']['active_incidents']} active incidents. Bridge-04 is the main infrastructure concern."
        evidence = [f"Security score: {data['summary']['security_score']}/100", f"Blockchain health: {data['summary']['blockchain_health']}%", f"Active incidents: {data['summary']['active_incidents']}"]
        next_steps = ["Run an integrity scan", "Review Bridge-04 evidence", "Open the incident response queue"]
        suggested_action = "run-scan"
    elif any(word in message for word in ["report", "pdf", "export"]):
        intent = "Reporting help"
        confidence = "High"
        answer = "Use Export PDF Report for the full report. It contains the score summary, graphical risk movement, explainable findings, node health, incidents, controls, and attribution limitations."
        evidence = ["PDF report uses the current verified telemetry snapshot", "Graphical risk movement is included", "Attribution limitations are documented"]
        next_steps = ["Export the PDF report", "Share it with the response team", "Attach preserved evidence separately"]
        suggested_action = "generate-report"
    elif any(word in message for word in ["solve", "fix", "recommend", "solution", "secure"]):
        intent = "Containment recommendation"
        confidence = "Medium"
        answer = "Start with operator-approved isolation for the affected wallet group, review Bridge-04 signing permissions, require multi-party approval for validator changes, and preserve logs before closing INC-2048."
        evidence = ["Bridge-04 is in Review state at 61% health", "INC-2048 is the highest priority incident", "7 wallets are flagged"]
        next_steps = ["Prepare wallet isolation", "Review bridge signing permissions", "Escalate INC-2048 with evidence"]
        suggested_action = "isolate-wallet"
    else:
        intent = "Getting started"
        confidence = "High"
        answer = "I am Shravi.ai. Ask me about the security score, findings, incidents, node health, PDF reports, recommended controls, or evidence required for attacker attribution."
        evidence = ["CYBERSATHI verified telemetry snapshot", "4 explainable signals available", "3 active incidents available"]
        next_steps = ["Ask: Why is the score high?", "Ask: What should I fix first?", "Ask: What evidence identifies an attacker?"]
        suggested_action = None
    return {"assistant": "Shravi.ai", "answer": answer, "intent": intent, "confidence": confidence, "evidence": evidence, "next_steps": next_steps, "suggested_action": suggested_action, "timestamp": now_iso(), "evidence_basis": "CYBERSATHI verified telemetry snapshot"}
