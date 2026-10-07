"""Unit tests for rows of the "BRD Traceability" sheet closed after revision 3.

Pure logic only; database paths are covered by the end-to-end run against Postgres.
"""

import re

import pytest
from dpdpcms_py import pdfgen
from dpdpcms_py.context import RequestContext
from dpdpcms_py.errors import ApiError
from dpdpcms_py.services import compliance, consent, roles

FID = "11111111-1111-1111-1111-111111111111"

POLICY = {
    "en": {
        "data_processing_purposes": [
            {"id": "care", "name": "Care", "is_mandatory_for_service": True},
            {"id": "research", "name": "Research", "is_mandatory_for_service": False},
        ]
    }
}


def _ctx(category="client", payload=None, headers=None, **kwargs):
    return RequestContext(
        path="/api/v1/client/consent",
        category=category,
        service="consent",
        payload={"_func": "record_consent", **(payload or {})},
        headers=headers or {},
        **kwargs,
    )


# ── CC-03 granular, explicit, unbundled consent ──────────────────────
def test_every_purpose_needs_an_explicit_boolean():
    consent.check_explicit_choices(
        POLICY,
        [{"data_point_id": "care", "consent_granted": True}, {"data_point_id": "research", "consent_granted": False}],
    )
    with pytest.raises(ApiError, match="explicit"):
        consent.check_explicit_choices(
            POLICY,
            [
                {"data_point_id": "care", "consent_granted": True},
                {"data_point_id": "research", "consent_granted": "yes"},
            ],
        )


def test_omitted_purpose_is_rejected_not_implied():
    with pytest.raises(ApiError, match="research"):
        consent.check_explicit_choices(POLICY, [{"data_point_id": "care", "consent_granted": True}])


def test_duplicate_purpose_rejected():
    with pytest.raises(ApiError, match="more than once"):
        consent.check_explicit_choices(
            POLICY,
            [
                {"data_point_id": "care", "consent_granted": True},
                {"data_point_id": "CARE", "consent_granted": False},
                {"data_point_id": "research", "consent_granted": False},
            ],
        )


# ── CC-04 / CC-06 server-observed capture metadata ───────────────────
def test_mechanism_and_ip_are_observed_not_claimed():
    ctx = _ctx(
        payload={"consent_mechanism": "PAPER_FORM", "ip_address": "1.2.3.4"},
        headers={"user-agent": "UA/1"},
        source_ip="203.0.113.9",
    )
    meta = consent._observed_metadata(ctx)
    assert meta["mechanism"] == "INTEGRATOR_API"
    assert meta["ip_address"] == "203.0.113.9"
    assert meta["user_agent"] == "UA/1"
    # The caller's claims are kept, but apart.
    assert meta["client_metadata"] == {"consent_mechanism": "PAPER_FORM", "ip_address": "1.2.3.4"}


def test_principal_session_id_comes_from_the_cms():
    ctx = _ctx(payload={"session_id": "client-says"}, auth_via_principal_jwt=True, session_id="jti-123")
    meta = consent._observed_metadata(ctx)
    assert meta["mechanism"] == "PRINCIPAL_PORTAL"
    assert (meta["session_id"], meta["session_source"]) == ("jti-123", "CMS")


def test_integrator_session_id_is_labelled_a_claim():
    meta = consent._observed_metadata(_ctx(payload={"session_id": "s-1"}))
    assert (meta["session_id"], meta["session_source"]) == ("s-1", "CLIENT")


# ── CC-05 guardian verification ──────────────────────────────────────
def test_digilocker_without_verifier_stays_pending():
    status, detail = consent._verify_with_digilocker("f", "g", "ref")
    assert status == "PENDING" and "DIGILOCKER_VERIFY_URL" in detail


# ── GR-02 / GR-11 grievance rules ───────────────────────────────────
def test_unknown_grievance_type_rejected(monkeypatch):
    monkeypatch.setattr(compliance.db, "insert_returning", lambda *a, **k: pytest.fail("must validate first"))
    ctx = _ctx(payload={"user_id": "u", "fiduciary_id": "f", "type": "whatever", "subject": "s", "description": "d"})
    with pytest.raises(ApiError) as exc:
        compliance.GrievanceService().submit_grievance(ctx)
    assert exc.value.status == 400


def test_resolving_requires_a_summary(monkeypatch):
    monkeypatch.setattr(compliance.db, "one", lambda *a, **k: pytest.fail("must validate first"))
    ctx = _ctx(category="admin", payload={"grievance_id": "g", "status": "RESOLVED", "resolution_details": " "})
    with pytest.raises(ApiError, match="resolution_details"):
        compliance.GrievanceService().update_grievance_status(ctx)


def test_feedback_rating_range():
    ctx = _ctx(payload={"user_id": "u", "grievance_id": "g", "rating": 9})
    with pytest.raises(ApiError, match="1 to 5"):
        compliance.GrievanceService().submit_grievance_feedback(ctx)


def test_attachment_type_allow_list():
    ctx = _ctx(
        payload={
            "grievance_id": "g",
            "content_type": "application/x-msdownload",
            "file_name": "a.exe",
            "content_base64": "AA==",
        }
    )
    with pytest.raises(ApiError, match="content_type"):
        compliance.GrievanceService().upload_grievance_attachment(ctx)


# ── SA-09 purge confirmation needs evidence ─────────────────────────
def test_confirm_purge_requires_record_count():
    ctx = _ctx(payload={"purge_request_id": "p", "status": "PURGE_COMPLETED", "records_affected_count": "lots"})
    with pytest.raises(ApiError, match="integer"):
        compliance.ComplianceService().confirm_purge_status(ctx)


# ── SA-07 / CW-04 permissions for the new admin functions ────────────
def test_new_functions_map_to_read_permissions():
    assert roles.required_permission("audit", "list_access_report") == "audit:read"
    assert roles.required_permission("consent", "get_withdrawal_implications") == "consent:read"


# ── UD-04 PDF export ────────────────────────────────────────────────
def test_pdf_is_well_formed_and_paginates():
    pdf = pdfgen.text_pdf("Consent history", [f"line {i} (with parens) and \\ backslash" for i in range(200)])
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    pages = int(re.search(rb"/Count (\d+)", pdf).group(1))
    assert pages > 1  # 200 lines + header span several A4 pages
    assert pdf.count(b"/Type /Page\n") == pages


def test_pdf_renders_eighth_schedule_scripts_without_replacement():
    # The Latin-1 writer turned all of these into '?'. Each script must pull in
    # the font that covers it, and only that font.
    samples = {
        "NotoSansDevanagari": "चिकित्सा परामर्श",
        "NotoSansBengali": "চিকিৎসা পরামর্শ",
        "NotoSansTamil": "மருத்துவ ஆலோசனை",
        "NotoNaskhArabic": "طبی مشورہ",
        "NotoSansOlChiki": "ᱥᱟᱱᱛᱟᱲᱤ",
        "NotoSansMeeteiMayek": "ꯃꯤꯇꯩꯂꯣꯟ",
    }
    for font, text in samples.items():
        assert pdfgen._fonts_for(f"Purposes: {text}") == ["NotoSans", font]
    pdf = pdfgen.text_pdf("Consent history", [f"Purposes: {t}" for t in samples.values()])
    embedded = set(re.findall(rb"/BaseFont /\w+\+(\w+)", pdf))
    assert embedded == {b"NotoSans", *(f.encode() for f in samples)}


def test_pdf_text_is_extractable_in_its_own_script():
    fitz = pytest.importorskip("pymupdf")
    pdf = pdfgen.text_pdf("Consent history", ["Purposes: अनुसंधान (withdrawn)"])
    text = fitz.open(stream=pdf, filetype="pdf")[0].get_text()
    assert "अनुसंधान" in text and "?" not in text


def test_purpose_names_follow_the_consent_language():
    content = {
        "en": {"data_processing_purposes": [{"id": "research", "name": "Research"}]},
        "hi": {"data_processing_purposes": [{"id": "research", "name": "अनुसंधान"}]},
    }
    assert consent._purpose_names(content, "hi") == {"research": "अनुसंधान"}
    assert consent._purpose_names(content, "ta") == {"research": "Research"}  # falls back to English
    assert consent._purpose_names(None, "hi") == {}


def test_pdf_export_names_purposes_in_the_records_language(monkeypatch):
    from datetime import datetime

    rows = [
        {
            "timestamp": datetime(2026, 10, 1, 9, 30),
            "policy_id": "pol-1",
            "policy_version": 2,
            "language_selected": "hi",
            "consent_status_general": "ACTIVE",
            "is_active_consent": True,
            "data_point_consents": [{"data_point_id": "research", "consent_granted": False}],
            "policy_content": {"hi": {"data_processing_purposes": [{"id": "research", "name": "अनुसंधान"}]}},
        }
    ]
    captured = {}
    monkeypatch.setattr(consent.db, "all", lambda *a, **k: rows)
    monkeypatch.setattr(consent, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(pdfgen, "text_pdf", lambda title, lines: captured.setdefault("lines", lines) and b"%PDF")
    ctx = RequestContext(
        path="/api/v1/client/consent",
        category="client",
        service="consent",
        payload={"_func": "export_consent_history", "user_id": "asha", "format": "pdf"},
        headers={},
        fiduciary_id=FID,
    )
    consent.ConsentService().export_consent_history(ctx)
    assert "    - अनुसंधान (research): withdrawn" in captured["lines"]
