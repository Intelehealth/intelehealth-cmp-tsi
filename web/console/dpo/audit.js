// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        closeModal: () => closeModal(),
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

    // --- Configuration ---
    const API_URL_AUDIT = '/api/v1/admin/audit';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    if (localStorage.getItem('role') === 'OPERATOR') {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
    }
    document.getElementById('username').textContent = localStorage.getItem('username') || 'DPO User';

    let tableBody, countSpan, searchInput, actionFilter, modalOverlay;
    let currentLogs = []; // Global variable to store fetched logs for export

    function toggleMenu() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebar-backdrop').classList.toggle('hidden');
    }

    function closeModal() { modalOverlay.style.display = 'none'; }

    function getActorTag(type, id) {
        let tagClass = 'tag-system';
        if (type === 'APP') tagClass = 'tag-app';
        if (type === 'USER') tagClass = 'tag-user';

        return `
            <div class="flex flex-col gap-0.5">
                <span class="actor-tag ${tagClass}">${esc(type)}</span>
                <span class="text-[9px] font-mono text-gray-400 truncate max-w-[120px]" title="${esc(id)}">ID: ${esc(id || 'N/A')}</span>
            </div>
        `;
    }

    function createLogRow(log) {
        const row = document.createElement('tr');
        row.className = 'hover:bg-slate-50 transition-colors cursor-default align-top';

        // Format action badge
        const criticalActions = ['WEBHOOK_DELIVERY_FAILED', 'BREACH_REPORTED', 'PURGE_FAILED'];
        const actionClass = criticalActions.includes(log.audit_action)
            ? 'bg-red-50 text-red-700 border-red-100'
            : log.audit_action === 'LEGAL_HOLD_APPLIED'
            ? 'bg-blue-50 text-blue-700 border-blue-100'
            : log.audit_action.includes('WITHDRAWN') || log.audit_action.includes('ERASURE') || log.audit_action.includes('VALIDATION_FAILED')
            ? 'bg-red-50 text-red-700 border-red-100'
            : 'bg-teal-50 text-teal-700 border-teal-100';

        // Format context details for inline display
        const context = log.context_details;
        const contextDisplay = typeof context === 'string' ? context : JSON.stringify(context, null, 2);

        row.innerHTML = `
            <td class="px-4 py-3 whitespace-nowrap">
                <p class="text-sm font-semibold text-gray-700">${esc(new Date(log.timestamp).toLocaleDateString())}</p>
                <p class="text-[10px] text-gray-400 font-bold uppercase">${esc(new Date(log.timestamp).toLocaleTimeString())}</p>
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
                <span class="text-sm font-mono text-gray-600 bg-gray-100 px-2 py-0.5 rounded">${esc(log.user_id)}</span>
            </td>
            <td class="px-4 py-3 whitespace-nowrap">
                <span class="text-[11px] font-bold px-2 py-1 rounded border ${actionClass}">${esc(log.audit_action)}</span>
            </td>
            <td class="px-4 py-3 whitespace-nowrap">${getActorTag(log.service_type, log.service_id)}</td>
            <td class="px-4 py-3 min-w-[300px]">
                <div class="bg-slate-50 border border-slate-200 rounded-lg p-3 font-mono text-[10px] text-slate-600 overflow-x-auto max-h-[150px] scrollbar-thin">
                    <pre class="whitespace-pre-wrap break-words">${esc(contextDisplay || "{}")}</pre>
                </div>
            </td>
        `;
        return row;
    }

    async function loadLogs() {
        tableBody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-gray-400 italic">Fetching logs...</td></tr>`;

        try {
            const response = await fetch(API_URL_AUDIT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({
                    "_func": "list_audit_logs",
                    "fiduciary_id": FIDUCIARY_ID,
                    "search": searchInput.value,
                    "action_filter": actionFilter.value === 'ALL' ? '' : actionFilter.value,
                    "limit": 50
                })
            });

            const data = await response.json();

             if (data.status === 401) {
                alert("Auth Failed: " + (data.message || "Authentication required."));
                handleLogout();
                return;
            }

            const logs = data.data || data;

            currentLogs = logs; // Store for export
            tableBody.innerHTML = '';
            if (!logs || logs.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-gray-500">No audit records found for this principal/filter.</td></tr>`;
            } else {
                logs.forEach(l => tableBody.appendChild(createLogRow(l)));
            }
            countSpan.textContent = `Displaying latest ${logs.length || 0} events`;

        } catch (error) {
            console.error("Audit load error:", error);
            tableBody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-red-500 font-bold">Failed to load audit trail: ${esc(error.message)}</td></tr>`;
        }
    }

    async function inspectArtifact(id) {
        try {
            const response = await fetch(API_URL_AUDIT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_audit_log", "id": id, "fiduciary_id": FIDUCIARY_ID })
            });

            // Handle Unauthorized Access (Session Expired)
            if (response.status === 401) {
                handleLogout();
                return;
            }

            if (!response.ok) {
                console.error("Inspect failed. Status:", response.status);
                return;
            }

            const log = await response.json();
            const context = log.context_details || log.data?.context_details;

            document.getElementById('modal-log-id').textContent = `Log Ref: ${id}`;
            const contextDisplay = typeof context === 'string' ? context : JSON.stringify(context, null, 2);
            document.getElementById('modal-context-content').textContent = contextDisplay || "{}";

            modalOverlay.style.display = 'flex';
        } catch (e) { console.error("Error fetching context artifact:", e); }
    }

    /**
     * XLS Export Utility using SheetJS
     */
    function downloadXLS() {
        if (!currentLogs || currentLogs.length === 0) {
            alert("No data available to download. Please ensure logs are loaded first.");
            return;
        }

        // Prepare data for Excel (Flattening objects for spreadsheet readability)
        const dataForExcel = currentLogs.map(log => ({
            "Timestamp": new Date(log.timestamp).toLocaleString(),
            "Principal ID": log.user_id,
            "Action Type": log.audit_action,
            "Actor Type": log.service_type,
            "Actor ID": log.service_id,
            "Context Details": typeof log.context_details === 'object'
                ? JSON.stringify(log.context_details)
                : log.context_details,
            // P9-08 / LG-07: the remaining hashed columns and both hashes, so the
            // exported ledger can be re-verified by whoever receives it.
            "Log ID": log.id,
            "Fiduciary ID": log.fiduciary_id,
            "Purpose ID": log.purpose_id,
            "Consent Status": log.consent_status,
            "Initiator": log.initiator,
            "Source IP": log.source_ip,
            "Raw Timestamp (UTC)": log.timestamp,
            "Previous Log Hash": log.prev_log_hash,
            "Current Log Hash": log.current_log_hash,
            // P10-06 / LG-07: system_metadata carries the hash version the row
            // was sealed under; without it the row cannot be re-verified.
            "System Metadata": log.system_metadata == null ? ''
                : (typeof log.system_metadata === 'object' ? JSON.stringify(log.system_metadata) : log.system_metadata)
        }));

        // Generate worksheet and workbook
        const worksheet = XLSX.utils.json_to_sheet(dataForExcel);
        const workbook = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(workbook, worksheet, "Audit Trail");

        // Format column widths for better default view
        const wscols = [
            { wch: 20 }, // Timestamp
            { wch: 25 }, // Principal ID
            { wch: 20 }, // Action Type
            { wch: 12 }, // Actor Type
            { wch: 36 }, // Actor ID
            { wch: 50 }, // Context Details
            { wch: 36 }, // Log ID
            { wch: 20 }, // Purpose ID
            { wch: 16 }, // Consent Status
            { wch: 12 }, // Initiator
            { wch: 16 }, // Source IP
            { wch: 28 }, // Raw Timestamp (UTC)
            { wch: 64 }, // Previous Log Hash
            { wch: 64 }  // Current Log Hash
        ];
        worksheet['!cols'] = wscols;

        // Generate filename with timestamp
        const dateStamp = new Date().toISOString().split('T')[0];
        const filename = `TSI_Audit_Report_${FIDUCIARY_ID || 'Global'}_${dateStamp}.xlsx`;

        // Trigger native browser download
        XLSX.writeFile(workbook, filename);
    }

    // SEC-10: surface the chain verifier in the DPO console. The service is
    // admin-only and requires a global (unscoped) operator to run.
    async function verifyChain() {
        const btn = document.getElementById('verify-chain-btn');
        const result = document.getElementById('verify-chain-result');
        btn.disabled = true;
        result.textContent = 'Checking…';
        try {
            const response = await fetch(API_URL_AUDIT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "verify_audit_chain", "limit": 100000 })
            });
            const body = await response.json();
            if (response.status === 403) {
                result.textContent = 'Verify Chain requires a global administrator session.';
            } else if (response.ok && body.unexamined_tenant) {
                // P8-05: "not verified" is not "verified broken". The window held
                // none of this tenant's rows, so nothing was examined.
                result.textContent = `NOT VERIFIED: the checked window held none of your ${body.rows_in_scope_total || 0} audit rows`;
            } else if (response.ok && body.intact && body.coverage_complete === false) {
                result.textContent = `Chain intact for the window checked, but INCOMPLETE: ${body.rows_checked} of ${body.rows_in_scope_total} rows examined`;
            } else if (response.ok && body.intact) {
                result.textContent = `Chain intact: ${body.rows_checked} rows checked`
                    + (body.legacy_rows_linkage_only ? ` (${body.legacy_rows_linkage_only} legacy linkage-only)` : '');
            } else if (response.ok && !body.broken_count && body.foreign_broken_count) {
                result.textContent = `Chain BROKEN outside your records: ${body.foreign_broken_count} break(s) in the shared ledger your entries link through`;
                console.warn('Audit chain verification failed', body);
            } else {
                const failed = body && body.broken_count !== undefined ? body.broken_count : (body.message || 'failed');
                result.textContent = `Chain BROKEN: ${failed}`;
                console.warn('Audit chain verification failed', body);
            }
            const full = body && body.last_full_verification;
            if (response.ok && full) {
                result.textContent += ` · last full-ledger check ${full.verified_at}: ${full.intact ? 'intact' : 'BROKEN'}`;
            }
        } catch (e) {
            result.textContent = 'Verification failed: ' + esc(e.message);
        } finally {
            btn.disabled = false;
        }
    }
    document.getElementById('verify-chain-btn').addEventListener('click', verifyChain);

    // Initialize DOM links and listeners
    tableBody = document.getElementById('audit-table-body');
    countSpan = document.getElementById('log-count');
    searchInput = document.getElementById('principal-search');
    actionFilter = document.getElementById('action-filter');
    modalOverlay = document.getElementById('audit-modal-overlay');

    document.getElementById('menu-toggle').addEventListener('click', toggleMenu);
    document.getElementById('sidebar-backdrop').addEventListener('click', toggleMenu);
    actionFilter.addEventListener('change', loadLogs);

    let searchTimeout;
    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(loadLogs, 300);
    });

    loadLogs();

    window.handleLogout = () => { localStorage.clear(); window.location.href = "../index.html"; };
