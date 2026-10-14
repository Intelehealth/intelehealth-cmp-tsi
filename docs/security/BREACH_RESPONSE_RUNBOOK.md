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
2. **Record.** Use the console's Breach page (`report_breach`). Give the true detection time, the affected purpose and/or the affected principal ids (a list or a CSV), and plain-language steps the principals should take.
   - The report notifies every principal it names. With no names, it notifies every principal who granted the affected purpose.
   - Each principal is notified once. `notify_affected_principals` can be re-run as more principals are identified.
3. **Decide.** The DPO decides whether the breach is notifiable. Rule 7 makes every personal data breach notifiable to the Board, so the default is yes.
4. **Intimate the Board** within 72 hours. Use the form and channel the Board prescribes. Then call `record_board_intimation` with the Board's acknowledgement or filing reference. A late filing is recorded as late, never hidden.
5. **Follow up.** The detailed Rule 7(2) report is due within 72 hours, or longer if the Board allows. It covers facts, cause, mitigation, remedial steps and the notices sent. The breach PDF report (`download_breach_report`) is available once the breach is CONTAINED or RESOLVED.
6. **Close.** Set the status to RESOLVED with resolution notes. Hold a post-incident review within 14 days.

## Exercise log

Run a tabletop exercise twice a year: a synthetic breach, recorded in a staging tenant, taken through to a mock Board intimation.

| Date | Scenario | Time to decision | Time to (mock) intimation | Lessons |
| --- | --- | --- | --- | --- |
| | | | | |
