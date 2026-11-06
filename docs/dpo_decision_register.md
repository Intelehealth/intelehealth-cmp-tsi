# DPO decision register

Decisions in which Intelehealth departs from the literal text of the MeitY/NeGD
BRD for Consent Management under the DPDP Act 2023. Each entry records the
statutory basis, the control that replaces the BRD mechanism, and what the
decision does to the traceability matrix. A requirement marked *Not applicable*
on the traceability sheet always points back to an entry here.

The Data Protection Officer owns this register. Review it whenever the product
changes in a way that could make an entry's factual basis untrue, and at least
once a year.

**Named owners.** Each role below must be filled with a named person, and the
name recorded here, before the register is relied on in an audit. Until then
the "Named holder" column reads *to be named*.

| Ref | Decision | Owner (role) | Named holder | Recorded | Last checked | Next review |
|-----|----------|--------------|--------------|----------|--------------|-------------|
| DD-01 | Consent is open-ended | Data Protection Officer | *to be named* | Sep 2026 | 15 Oct 2026 | 15 Apr 2027 |
| DD-02 | "Active consents with expiration dates" is read as state plus horizon | Data Protection Officer | *to be named* | Sep 2026 | 15 Oct 2026 | 15 Oct 2027 |
| DD-03 | Clinical and research purposes carry no expiry | Data Protection Officer / Clinical lead | *to be named* | Sep 2026 | 15 Oct 2026 | 15 Apr 2027 |
| DD-04 | No cookie beyond strictly necessary, so BRD 4.2 does not apply | Data Protection Officer | *to be named* | Oct 2026 | 15 Oct 2026 | 15 Apr 2027, and whenever `web/` gains a script or tag |
| DD-05 | Recurring purpose-validity review | Data Protection Officer | *to be named* | Oct 2026 | - | First review by 15 Jan 2027, then quarterly |

## DD-01 — Consent is open-ended

**Decision.** A consent is valid from the moment it is given until the Data
Principal withdraws it, or until the purpose it was given for is closed. No
consent record carries an expiry date, and no consent is auto-expired by time.

**Enforced in code.** `record_consent` and `request_reconsent` refuse a
decision carrying `consent_expiry` or any other key outside the decision
schema (P12-01/P12-02, branch `p11_changes` remediation), so an integrator
cannot create the expiring consent this decision rules out.

**Statutory basis.** DPDP Act 2023 s.6(1) requires consent to be free,
specific, informed, unconditional and unambiguous; it imposes no maximum
duration. s.6(4)-(6) make withdrawal the mechanism by which consent ends.
s.8(7) ties erasure to withdrawal or to the purpose no longer being served. The
DPDP Rules 2025 contain no consent-validity period.

**What replaces the BRD mechanism.** Two independent dimensions: the purpose
lifecycle (OPEN / CLOSED per purpose; closing a purpose invalidates every
consent resting on it) and the retention clock (a per-purpose retention period
that runs from cessation, independent of consent state).

**Matrix.** BRD 4.1.4 Consent Renewal (nine requirements) is *Not applicable*,
replaced by PL-01 to PL-04 under 4.1.4-ALT. CU-10 is *Not applicable*.

## DD-02 — State plus horizon

**Decision.** "Display all active consents with their purposes, expiration
dates and metadata" (BRD 4.1.3) is read as two orthogonal facts: STATE (active /
withdrawn / invalidated — may we process today) and HORIZON (until when, where
a horizon exists).

**Basis.** Interpretive. The BRD is a reference design written for sectors in
which consent is time-boxed by sectoral regulation.

**What replaces the BRD mechanism.** Where the dashboard would show an expiry
date it shows the purpose's lifecycle state and the governing retention period.

**Matrix.** UD-02 is met by the substitution; no requirement is waived on this
reading alone.

## DD-03 — Clinical and research purposes carry no expiry

**Decision.** Clinical records are retained for the statutory medical-record
period; research and analytics continue for the life of the project.

**Statutory basis.** Clinical Establishments (Central Government) Rules 2012
and the ICMR National Ethical Guidelines require medical records to be kept for
defined periods independent of consent; DPDP Act s.7 and the s.8(7) proviso
allow retention another law requires.

**What replaces the BRD mechanism.** Retention is set per data category (a
seven-year statutory floor is enforced for health records). Withdrawal stops
further processing and triggers erasure of everything the statutory period does
not compel the fiduciary to keep.

**Matrix.** No requirement row is waived on this entry alone. What makes it
safe is the recurring purpose-validity review (DD-05): without a recorded,
recurring review, open-ended consent is indistinguishable from indefinite
consent, which s.8(7) forbids. (An earlier note called that review PL-03; PL-03
is closure-triggered erasure, which is met in code.)

## DD-04 — No cookie beyond strictly necessary

**Decision.** Intelehealth's web properties set no cookie beyond what is
strictly necessary to operate the service, so the BRD's Cookie Consent module
(4.2, CK-01 to CK-10) does not apply.

**Statutory basis.** DPDP Act 2023 s.5 and s.6 with Rule 3 require notice and
consent for processing personal data. A strictly-necessary cookie that carries
no personal data and enables a service the principal asked for is not
processing that requires separate consent; the notice obligation is discharged
by the policy served at CC-01 and CC-02.

**Factual basis, verified (15 Oct 2026).** No page under `web/` writes
`document.cookie`; the console and the rights portal keep their tokens in
session or local storage; the server sets no `Set-Cookie` header and runs no
session middleware. No analytics or embedded media is loaded, and since the
P12-08 change no third-party script, stylesheet or font is loaded either: the
three libraries the pages use (Tailwind, qrcodejs, SheetJS) are served from
`web/vendor/`, and the Content-Security-Policy (`script-src 'self'`) refuses
any other origin. Outbound links (for example the tour's video links) open a
new page and load nothing into ours.

**Condition.** The decision holds only while that fact is true. If any
analytics, embedded-media or third-party tag is ever added, CK-01 to CK-10
become live requirements again and Rule 3 notice applies. Re-check the fact
whenever `web/` gains a script or a tag.

**Matrix.** CK-01 to CK-10 move from *Missing* to *Not applicable*.

## DD-05 — Recurring purpose-validity review

**Decision.** Because consent is open-ended (DD-01) and clinical and research
purposes carry no expiry (DD-03), the DPO reviews every OPEN purpose of every
fiduciary at least once a quarter and records, for each, whether the purpose is
still being served.

**Statutory basis.** DPDP Act 2023 s.8(7): personal data is erased once the
purpose is no longer being served (unless another law requires retention).
Without a recurring review, nothing establishes that it still is.

**Procedure.** [docs/security/PURPOSE_VALIDITY_REVIEW.md](security/PURPOSE_VALIDITY_REVIEW.md).
A purpose found no longer served is closed with `close_purpose` (PL-02), which
invalidates the consents resting on it and raises erasure or
de-identification under its retention schedule (PL-03).

**Record.** The review log table in that document: date, reviewer (named),
fiduciary, purposes reviewed, purposes closed, and the reason for each one
kept open.

**Matrix.** Supports DD-01 and DD-03; it is the control that keeps the nine
Consent Renewal rows and CU-10 *Not applicable* on honest ground.
