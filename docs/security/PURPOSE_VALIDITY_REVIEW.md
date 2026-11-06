# Purpose-validity review (s.8(7); DPO register DD-05)

Consent at Intelehealth is open-ended (DD-01), and clinical and research
purposes carry no expiry (DD-03). What stops open-ended consent becoming
indefinite consent is this review: a recorded check, at least once a quarter,
that every OPEN purpose is still being served. s.8(7) requires erasure once it
is not.

## Who and when

- **Owner:** the Data Protection Officer (name recorded in the DPO register).
- **Participants:** the product lead for each fiduciary; the clinical lead for clinical and research purposes.
- **Cadence:** quarterly, and whenever a product, study or programme ends.
  First review due by 15 Jan 2027.

## Steps

1. List the OPEN purposes of each fiduciary: `list_purpose_lifecycle` (console:
   Policies, purpose lifecycle).
2. For each purpose, ask: is the activity it describes still running? Is the
   data still used for it? For research, is the study still open under its
   ethics approval?
3. Where the answer is no, close it with `close_purpose` (PL-02). That
   invalidates every consent resting on it and raises erasure or
   de-identification under its retention schedule (PL-03), deferred where a
   statutory retention period still runs (DD-03).
4. Where the answer is yes, record why in one line.
5. Record the review below and sign it.

## Review log

| Date | Reviewer (named) | Fiduciary | Purposes reviewed | Purposes closed | Kept open, and why |
| --- | --- | --- | --- | --- | --- |
| | | | | | |
