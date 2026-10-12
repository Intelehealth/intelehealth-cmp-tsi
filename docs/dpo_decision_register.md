# DPO decision register

Decisions in which Intelehealth departs from the literal text of the MeitY/NeGD
BRD for Consent Management under the DPDP Act 2023. Each entry records the
statutory basis, the control that replaces the BRD mechanism, and what the
decision does to the traceability matrix. A requirement marked *Not applicable*
on the traceability sheet always points back to an entry here.

The Data Protection Officer owns this register. Review it whenever the product
changes in a way that could make an entry's factual basis untrue, and at least
once a year.

| Ref | Decision | Owner | Recorded |
|-----|----------|-------|----------|
| DD-01 | Consent is open-ended | Data Protection Officer | 2026 |
| DD-02 | "Active consents with expiration dates" is read as state plus horizon | Data Protection Officer | 2026 |
| DD-03 | Clinical and research purposes carry no expiry | Data Protection Officer / Clinical lead | 2026 |
| DD-04 | No cookie beyond strictly necessary, so BRD 4.2 does not apply | Data Protection Officer | 2026 |

## DD-01 — Consent is open-ended

**Decision.** A consent is valid from the moment it is given until the Data
Principal withdraws it, or until the purpose it was given for is retired. No
consent record carries an expiry date, and no consent is auto-expired by time.

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

**Matrix.** PL-03 (periodic purpose-validity review) is load-bearing: without a
recorded, recurring review, open-ended consent is indistinguishable from
indefinite consent.

## DD-04 — No cookie beyond strictly necessary

**Decision.** Intelehealth's web properties set no cookie beyond what is
strictly necessary to operate the service, so the BRD's Cookie Consent module
(4.2, CK-01 to CK-10) does not apply.

**Statutory basis.** DPDP Act 2023 s.5 and s.6 with Rule 3 require notice and
consent for processing personal data. A strictly-necessary cookie that carries
no personal data and enables a service the principal asked for is not
processing that requires separate consent; the notice obligation is discharged
by the policy served at CC-01 and CC-02.

**Factual basis, verified.** No page under `web/` writes `document.cookie`;
the console and the rights portal keep their tokens in session or local
storage; the server sets no `Set-Cookie` header and runs no session middleware;
no analytics, embedded-media or third-party tag is loaded.

**Condition.** The decision holds only while that fact is true. If any
analytics, embedded-media or third-party tag is ever added, CK-01 to CK-10
become live requirements again and Rule 3 notice applies. Re-check the fact
whenever `web/` gains a script or a tag.

**Matrix.** CK-01 to CK-10 move from *Missing* to *Not applicable*.
