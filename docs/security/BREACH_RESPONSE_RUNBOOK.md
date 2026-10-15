# Personal data breach runbook (s.8(6), Rule 7)

## Roles

| Role | Who | Duty |
| --- | --- | --- |
| Incident lead | Infrastructure lead (fill in a name) | Containment, technical facts, timeline |
| Decision owner | DPO (fill in a name) | Decides whether the breach is notifiable; signs the Board intimation |
| Communications | DPO's delegate | Wording of the principal notice |

## Clock

The 72-hour Board deadline runs from **detection**: `detected_at` on the breach record, which `report_breach` turns into `board_notification_deadline`.

The internal target is to make the decision within 24 hours and file with the Board within 48 hours. The worker alerts the DPO 12 hours before the deadline, and again if the deadline passes unrecorded.

## Steps

1. **Contain.** Revoke the affected keys and sessions, and isolate the hosts involved.
2. **Record.** Use the console's Breach page (`report_breach`). Give the true detection time (a future one is refused), the affected purpose and/or the affected principal ids (a list or a CSV), and the Rule 7(1) contents of the principal notice: plain-language steps the principals should take, the likely consequences, the mitigation measures taken, and a contact point.
   - The report notifies every principal it names. With no names, it notifies every principal who granted the affected purpose.
   - Each principal is notified once. `notify_affected_principals` can be re-run as more principals are identified.
3. **Decide.** The DPO decides whether the breach is notifiable. Rule 7 makes every personal data breach notifiable to the Board, so the default is yes.
4. **Intimate the Board** within 72 hours. Use the form and channel the Board prescribes. Then call `record_board_intimation` with the Board's acknowledgement or filing reference.
   - The CMS records the intimation at **server time** (`board_notified_at`); the caller cannot set it.
   - If the Board was intimated earlier through another channel, give that time as `intimated_at`. It is stored separately (`board_intimated_at_asserted`), must lie between detection and now, and is what decides whether the filing was late. Both times appear in the audit event and the PDF report.
   - A late filing is recorded as late, never hidden.
5. **Follow up.** The detailed Rule 7(2)(b) report is due within 72 hours, or longer if the Board allows. Record its contents with `update_breach_status`: `circumstances` (events, circumstances and reasons), `mitigation_measures`, `cause_findings` (findings on the person who caused the breach) and `remedial_measures`. Tick "Record the detailed report as submitted" (`submit_detailed_report`) once it is filed; that stamps `board_report_submitted_at` and is refused while any of the four is missing.
   - `download_breach_report` renders the breach report as a real PDF, server-side. It carries every Rule 7(1) and 7(2)(b) field, the principal-notice time, both intimation times, the Board reference and whether the filing was late. The console offers it once the breach is CONTAINED or RESOLVED.
6. **Close.** Set the status to RESOLVED with resolution notes. Hold a post-incident review within 14 days.

## Exercise log

Run a tabletop exercise twice a year: a synthetic breach, recorded in a staging tenant, taken through to a mock Board intimation.

| Date | Scenario | Time to decision | Time to (mock) intimation | Lessons |
| --- | --- | --- | --- | --- |
| | | | | |
