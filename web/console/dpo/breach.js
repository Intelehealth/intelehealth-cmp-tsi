// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        openReportModal: () => openReportModal(),
        closeModal: (el) => closeModal(el.getAttribute('data-arg')),
        downloadReport: () => downloadReport(document.getElementById('status-update-form').getAttribute('data-id')),
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
})();

    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    const API_URL_BREACH = '/api/v1/admin/breach';
    const RULE7_FIELDS = ['likely_consequences', 'mitigation_measures', 'contact_point', 'circumstances', 'cause_findings', 'remedial_measures'];
    const API_URL_POLICY = '/api/v1/admin/policy';
    const API_URL_NOTIFICATION = '/api/v1/admin/notification';
    const BREACH_TYPE_PREFIX = 'BREACH_NOTIFICATION_';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    const IS_OPERATOR = localStorage.getItem('role') === 'OPERATOR';
    if (IS_OPERATOR) {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
        document.getElementById('report-breach-btn').remove();
        document.getElementById('status-update-form').style.display = 'none'; // hidden, not removed: init below still wires its (now invisible) submit listener
    }
    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'DPO User';

    let tableBody, countSpan, statusFilter, reportForm, statusUpdateForm;

    function toggleMenu() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebar-backdrop').classList.toggle('hidden');
    }

    function closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
    }

    function openReportModal() {
        document.getElementById('report-modal-overlay').style.display = 'flex';
    }

    function createStatusBadge(status) {
        let colorClass = '';
        switch (status) {
            case 'OPEN': colorClass = 'bg-red-100 text-red-800'; break;
            case 'CONTAINED': colorClass = 'bg-yellow-100 text-yellow-800'; break;
            case 'RESOLVED': colorClass = 'bg-green-100 text-green-800'; break;
            default: colorClass = 'bg-gray-100 text-gray-800';
        }
        return `<span class="px-3 py-1 text-xs font-medium rounded-full ${colorClass}">${esc(status)}</span>`;
    }

    function createSeverityBadge(severity) {
        let colorClass = '';
        switch (severity) {
            case 'LOW': colorClass = 'bg-slate-100 text-slate-700'; break;
            case 'MEDIUM': colorClass = 'bg-amber-100 text-amber-800'; break;
            case 'HIGH': colorClass = 'bg-orange-100 text-orange-800'; break;
            case 'CRITICAL': colorClass = 'bg-red-100 text-red-800'; break;
            default: colorClass = 'bg-gray-100 text-gray-800';
        }
        return `<span class="px-2 py-0.5 text-[10px] font-bold rounded-full uppercase ${colorClass}">${esc(severity)}</span>`;
    }

    function createBreachRow(b) {
        const row = document.createElement('tr');
        const reportAvailable = b.status === 'CONTAINED' || b.status === 'RESOLVED';
        const downloadButton = reportAvailable
            ? `<button class="download-report-row-btn text-slate-600 hover:text-slate-900 font-medium ml-3" data-id="${esc(b.id)}">Download PDF</button>`
            : '';
        row.innerHTML = `
            <td class="px-4 py-3 text-sm font-medium text-gray-800">${esc(b.title)}</td>
            <td class="px-4 py-3 text-sm">${createSeverityBadge(b.severity)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(b.affected_principal_count)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(new Date(b.reported_at).toLocaleDateString())}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm">${createStatusBadge(b.status)}</td>
            <td class="px-4 py-3 text-sm">
                <button class="view-breach-btn text-indigo-600 hover:text-indigo-900 font-medium" data-id="${esc(b.id)}">Manage</button>${downloadButton}
            </td>
        `;
        row.querySelector('.view-breach-btn').addEventListener('click', () => viewBreach(b.id));
        const dlBtn = row.querySelector('.download-report-row-btn');
        if (dlBtn) dlBtn.addEventListener('click', () => downloadReport(b.id));
        return row;
    }

    async function loadBreaches() {
        tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">Loading breach incidents...</td></tr>`;
        try {
            const payload = {
                "_func": "list_breaches",
                "fiduciary_id": FIDUCIARY_ID,
                "status": statusFilter.value === 'ALL' ? '' : statusFilter.value
            };
            const response = await fetch(API_URL_BREACH, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (data.status === 401) {
                alert("Session Expired: " + (data.message || "Authentication required."));
                handleLogout();
                return;
            }
            const breaches = data || [];
            tableBody.innerHTML = '';
            if (breaches.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">No breach incidents recorded.</td></tr>`;
            } else {
                breaches.forEach(b => tableBody.appendChild(createBreachRow(b)));
            }
            countSpan.textContent = `Total: ${breaches.length} Incidents`;
        } catch (error) {
            tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-red-600">Failed to load breach incidents.</td></tr>`;
        }
    }

    async function loadPurposeOptions() {
        const select = document.getElementById('breach-purpose');
        try {
            const response = await fetch(API_URL_POLICY, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_active_policy", "fiduciary_id": FIDUCIARY_ID, "jurisdiction": "IN" })
            });
            const policy = await response.json();
            const langContent = policy && policy.policy_content ? policy.policy_content.en : null;
            const purposes = langContent ? (langContent.data_processing_purposes || []) : [];
            purposes.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.id;
                opt.textContent = p.name;
                select.appendChild(opt);
            });
        } catch (e) {
            console.error("Could not load active policy purposes", e);
        }
    }

    // Populates the Breach Category dropdown from whatever breach types the DPO has
    // already defined in Settings (set_notification_message under BREACH_NOTIFICATION_*).
    async function loadBreachCategoryOptions() {
        const select = document.getElementById('breach-category');
        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_notification_messages", "fiduciary_id": FIDUCIARY_ID })
            });
            const rows = await response.json();
            (rows || [])
                .filter(row => row.notification_type && row.notification_type.startsWith(BREACH_TYPE_PREFIX))
                .forEach(row => {
                    const code = row.notification_type.substring(BREACH_TYPE_PREFIX.length);
                    const opt = document.createElement('option');
                    opt.value = code;
                    opt.textContent = code.charAt(0).toUpperCase() + code.slice(1).toLowerCase();
                    select.appendChild(opt);
                });
        } catch (e) {
            console.error("Could not load breach categories", e);
        }
    }

    async function viewBreach(id) {
        try {
            const response = await fetch(API_URL_BREACH, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_breach", "id": id })
            });
            const b = await response.json();

            document.getElementById('detail-title').textContent = b.title;
            document.getElementById('detail-severity').innerHTML = createSeverityBadge(b.severity);
            document.getElementById('detail-affected-count').textContent = b.affected_principal_count;
            document.getElementById('detail-notification-type').textContent = b.notification_type || 'BREACH_NOTIFICATION (generic)';
            document.getElementById('detail-status').innerHTML = createStatusBadge(b.status);
            document.getElementById('detail-detected').textContent = new Date(b.detected_at).toLocaleString();
            document.getElementById('detail-reported').textContent = new Date(b.reported_at).toLocaleString();
            document.getElementById('detail-description').textContent = b.description;
            document.getElementById('detail-actionable-steps').textContent = b.actionable_steps;
            document.getElementById('new-status').value = b.status;
            document.getElementById('resolution-notes').value = b.resolution_notes || '';
            RULE7_FIELDS.forEach((key) => {
                document.getElementById(`update-${key.replace(/_/g, '-')}`).value = b[key] || '';
            });
            document.getElementById('submit-detailed-report').checked = false;
            document.getElementById('submit-detailed-report').disabled = !!b.board_report_submitted_at;
            document.getElementById('detailed-report-status').textContent = b.board_report_submitted_at
                ? `Detailed report recorded ${new Date(b.board_report_submitted_at).toLocaleString()}.`
                : 'Detailed report not yet recorded.';

            const reportAvailable = b.status === 'CONTAINED' || b.status === 'RESOLVED';
            document.getElementById('download-report-btn').classList.toggle('hidden', !reportAvailable);
            document.getElementById('download-report-hint').classList.toggle('hidden', reportAvailable);

            document.getElementById('detail-board-deadline').textContent =
                b.board_notification_deadline ? new Date(b.board_notification_deadline).toLocaleString() : '-';
            document.getElementById('detail-board-status').textContent = b.board_notified_at
                ? `Intimated ${new Date(b.board_notified_at).toLocaleString()} (ref ${b.board_reference || '-'})`
                : 'Not recorded';
            document.getElementById('board-record-row').classList.toggle('hidden', !!b.board_notified_at || IS_OPERATOR);
            document.getElementById('notify-principals-btn').classList.toggle('hidden', IS_OPERATOR);
            document.getElementById('detail-principals-notified').textContent =
                b.principals_notified_at ? new Date(b.principals_notified_at).toLocaleString() : 'not yet';

            statusUpdateForm.setAttribute('data-id', id);
            document.getElementById('manage-modal-overlay').style.display = 'flex';
        } catch (e) { alert("Error fetching breach details."); }
    }

    async function downloadReport(id) {
        try {
            const response = await fetch(API_URL_BREACH, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "download_breach_report", "id": id })
            });
            if (!response.ok) { alert("Failed to generate PDF report."); return; }
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `breach-report-${id}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (e) {
            alert("Network error while downloading report.");
        }
    }

    // --- Init ---
    tableBody = document.getElementById('breach-table-body');
    countSpan = document.getElementById('breach-count');
    statusFilter = document.getElementById('status-filter');
    reportForm = document.getElementById('report-form');
    statusUpdateForm = document.getElementById('status-update-form');

    document.getElementById('menu-toggle').addEventListener('click', toggleMenu);
    document.getElementById('sidebar-backdrop').addEventListener('click', toggleMenu);
    statusFilter.addEventListener('change', loadBreaches);

    function readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    document.getElementById('breach-user-ids-csv').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        const summary = document.getElementById('breach-csv-summary');
        if (!file) {
            summary.textContent = '';
            return;
        }
        const content = await readFileAsText(file);
        const count = content.split(/\r?\n/).map(l => l.trim()).filter(l => l).length;
        summary.textContent = `${count} Principal ID(s) found in ${file.name}.`;
    });

    reportForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = document.getElementById('report-submit-btn');
        btn.disabled = true;
        btn.textContent = 'Reporting...';

        try {
            const userIdsRaw = document.getElementById('breach-user-ids').value.trim();
            const affectedUserIds = userIdsRaw ? userIdsRaw.split(',').map(s => s.trim()).filter(s => s) : [];

            const csvFile = document.getElementById('breach-user-ids-csv').files[0];
            const affectedUserIdsCsv = csvFile ? await readFileAsText(csvFile) : undefined;

            const payload = {
                "_func": "report_breach",
                "fiduciary_id": FIDUCIARY_ID,
                "title": document.getElementById('breach-title').value,
                "description": document.getElementById('breach-description').value,
                "detected_at": new Date(document.getElementById('breach-detected-at').value).toISOString(),
                "severity": document.getElementById('breach-severity').value,
                "breach_category": document.getElementById('breach-category').value || undefined,
                "affected_purpose_id": document.getElementById('breach-purpose').value || undefined,
                "affected_user_ids": affectedUserIds.length ? affectedUserIds : undefined,
                "affected_user_ids_csv": affectedUserIdsCsv,
                "actionable_steps": document.getElementById('breach-actionable-steps').value,
                "likely_consequences": document.getElementById('breach-likely-consequences').value || undefined,
                "mitigation_measures": document.getElementById('breach-mitigation-measures').value || undefined,
                "contact_point": document.getElementById('breach-contact-point').value || undefined
            };

            const response = await fetch(API_URL_BREACH, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const result = await response.json();
                const message = `Breach reported. ${result.notified || 0} affected principal(s) notified. `
                    + `Intimate the Data Protection Board by ${new Date(result.board_notification_deadline).toLocaleString()} and record it here.`;
                alert(message);
                closeModal('report-modal-overlay');
                reportForm.reset();
                document.getElementById('breach-csv-summary').textContent = '';
                loadBreaches();
            } else {
                alert("Failed to report breach.");
            }
        } catch (err) {
            alert("Network error while reporting breach.");
        } finally {
            btn.disabled = false;
            btn.textContent = 'Report Breach & Notify Principals';
        }
    });

    statusUpdateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = statusUpdateForm.getAttribute('data-id');
        const btn = document.getElementById('status-update-btn');
        btn.disabled = true;
        btn.textContent = 'Saving...';

        try {
            const payload = {
                "_func": "update_breach_status",
                "id": id,
                "status": document.getElementById('new-status').value,
                "resolution_notes": document.getElementById('resolution-notes').value
            };
            // Rule 7(1) / 7(2)(b) contents: sent only when filled in.
            RULE7_FIELDS.forEach((key) => {
                const value = document.getElementById(`update-${key.replace(/_/g, '-')}`).value.trim();
                if (value) payload[key] = value;
            });
            if (document.getElementById('submit-detailed-report').checked) payload.submit_detailed_report = true;
            const response = await fetch(API_URL_BREACH, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });
            if (response.ok) {
                alert("Breach status updated.");
                closeModal('manage-modal-overlay');
                loadBreaches();
            } else {
                alert("Failed to update status.");
            }
        } finally {
            btn.disabled = false;
            btn.textContent = 'Save Status';
        }
    });

    async function breachCall(payload) {
        const response = await fetch(API_URL_BREACH, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
            body: JSON.stringify(payload)
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(body.message || body.error || 'Request failed');
        return body;
    }

    document.getElementById('board-record-btn').addEventListener('click', async () => {
        const id = statusUpdateForm.getAttribute('data-id');
        const reference = document.getElementById('board-reference').value.trim();
        if (!reference) { alert('Enter the Board acknowledgement or filing reference.'); return; }
        try {
            const intimatedAt = document.getElementById('board-intimated-at').value;
            const out = await breachCall({
                "_func": "record_board_intimation", "id": id, "board_reference": reference,
                ...(intimatedAt ? { "intimated_at": new Date(intimatedAt).toISOString() } : {})
            });
            alert(out.late ? 'Intimation recorded - after the 72-hour deadline.' : 'Intimation recorded.');
            viewBreach(id);
        } catch (e) { alert(`Could not record the intimation: ${e.message}`); }
    });

    document.getElementById('notify-principals-btn').addEventListener('click', async () => {
        const id = statusUpdateForm.getAttribute('data-id');
        try {
            const out = await breachCall({ "_func": "notify_affected_principals", "id": id });
            alert(`${out.notified} principal(s) notified; ${out.affected_total} affected in total.`);
            viewBreach(id);
            loadBreaches();
        } catch (e) { alert(`Could not notify principals: ${e.message}`); }
    });

    loadBreaches();
    loadPurposeOptions();
    loadBreachCategoryOptions();

    window.openReportModal = openReportModal;
    window.closeModal = closeModal;
    window.viewBreach = viewBreach;
    window.downloadReport = downloadReport;
    window.handleLogout = () => { localStorage.clear(); window.location.href = "../index.html"; };
