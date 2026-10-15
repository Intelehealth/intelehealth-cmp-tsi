// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        openDownloadsModal: () => openDownloadsModal(),
        openExportModal: () => openExportModal(),
        closeModals: () => closeModals(),
        loadJobs: () => loadJobs(),
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
        const API_URL_DASHBOARD = '/api/v1/admin/admindash';
        const API_URL_JOBS = '/api/v1/admin/job';
        const AUTH_TOKEN = localStorage.getItem('authToken');
        const USER_NAME = localStorage.getItem('username');

        // Defaulting to the Global Null UUID
        const FIDUCIARY_ID = localStorage.getItem('fiduciary_id') || '00000000-0000-0000-0000-000000000000';

        let auditActivityBody, auditErrorMessageP;
        let jobPollingInterval;

        // --- Utility Functions ---
        function toggleMenu() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('sidebar-backdrop').classList.toggle('hidden');
        }

        function closeModals() {
            document.querySelectorAll('.modal-overlay').forEach(m => m.style.display = 'none');
            if (jobPollingInterval) clearInterval(jobPollingInterval);
        }

        function openExportModal() {
            document.getElementById('export-modal').style.display = 'flex';
        }

        function openDownloadsModal() {
            document.getElementById('downloads-modal').style.display = 'flex';
            loadJobs();
            // Poll for updates while open
            jobPollingInterval = setInterval(loadJobs, 10000);
        }

        // --- Data Loading Functions ---

        async function loadDashboardMetrics() {
            try {
                const response = await fetch(API_URL_DASHBOARD, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ "_func": "get_admin_metrics" })
                });
                const data = await response.json();
                 if (data.status === 401) {
                    alert("Session Expired: " + (data.message || "Authentication required."));
                    handleLogout();
                    return;
                }
                if (data.success && data.metrics) {
                    const m = data.metrics;
                    document.getElementById('metric-fiduciaries-value').textContent = m.active_fiduciaries ?? '0';
                    document.getElementById('metric-processors-value').textContent = m.active_processors ?? '0';
                    document.getElementById('metric-purge-value').textContent = m.failed_purges ?? '0';
                }
            } catch (error) { console.error("Metrics load failed", error); }
        }

        async function loadRecentAuditActivity() {
            auditActivityBody.innerHTML = `<tr><td colspan="4" class="p-4 text-center text-gray-500">Fetching logs...</td></tr>`;
            try {
                const response = await fetch(API_URL_DASHBOARD, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ "_func": "list_access_logs", "limit": 10 })
                });
                const responseData = await response.json();
                const activities = responseData.data || responseData;
                if (Array.isArray(activities)) {
                    auditActivityBody.innerHTML = activities.length === 0
                        ? `<tr><td colspan="4" class="p-4 text-center text-gray-500">No recent activity.</td></tr>`
                        : activities.map(a => `
                            <tr>
                                <td class="px-4 py-3 text-sm text-gray-500 font-mono">${esc(new Date(a.timestamp).toLocaleString())}</td>
                                <td class="px-4 py-3 text-sm font-bold text-slate-700">${esc(a.user_id || 'SYSTEM')}</td>
                                <td class="px-4 py-3 text-sm"><span class="text-[10px] font-black uppercase text-teal-600">${esc(a.audit_action)}</span></td>
                                <td class="px-4 py-3 text-sm text-gray-500 truncate max-w-xs">${esc(a.context_details || '-')}</td>
                            </tr>
                        `).join('');
                }
            } catch (error) { auditActivityBody.innerHTML = `<tr><td colspan="4" class="p-4 text-center text-red-500">Error loading activity.</td></tr>`; }
        }

        async function loadJobs() {
            const tbody = document.getElementById('jobs-table-body');
            try {
                const response = await fetch(API_URL_JOBS, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ "_func": "list_jobs", "fiduciary_id": FIDUCIARY_ID })
                });
                const jobs = await response.json();
                const list = jobs.data || jobs;
                if (Array.isArray(list)) {
                    tbody.innerHTML = list.map(j => {
                        const isComplete = j.status === 'COMPLETED';
                        const statusColor = j.status === 'COMPLETED' ? 'bg-green-100 text-green-700' : (j.status === 'FAILED' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700');
                        return `
                            <tr class="hover:bg-slate-50 border-b border-slate-50">
                                <td class="py-3 font-mono text-[10px] text-slate-400">...${esc(j.id.slice(-8))}</td>
                                <td class="py-3 font-bold text-[11px] text-slate-700">${esc(j.subtype || j.job_type)}</td>
                                <td class="py-3 text-[10px] text-slate-500">${esc(new Date(j.created_at).toLocaleDateString())}</td>
                                <td class="py-3 text-center"><span class="px-2 py-0.5 rounded-full text-[9px] font-black ${statusColor}">${esc(j.status)}</span></td>
                                <td class="py-3 text-right">
                                    ${isComplete
                                        ? `<button data-jid="${esc(j.id)}" class="dl-job-btn text-teal-600 font-bold hover:underline text-[10px] uppercase flex items-center justify-end gap-1">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                            CSV
                                           </button>`
                                        : '<span class="text-slate-300 text-[9px] italic">Processing</span>'}
                                </td>
                            </tr>
                        `;
                    }).join('');
                    tbody.querySelectorAll('.dl-job-btn').forEach(btn => {
                        btn.addEventListener('click', () => downloadJobFile(btn.dataset.jid));
                    });
                }
            } catch (e) { console.error("Jobs load failed", e); }
        }

        function downloadJobFile(jobId) {
            // P6-03: the ?auth= query parameter was removed (SEC-17) and a browser
            // navigation cannot set an Authorization header, so the file is fetched
            // through the authenticated API and given to the browser as a blob.
            fetch(API_URL_JOBS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "download_file", "job_id": jobId })
            })
                .then(res => res.json())
                .then(data => {
                    if (!data.success) { alert(data.message || "Export file not ready."); return; }
                    const bytes = atob(data.content_base64);
                    const arr = new Uint8Array(bytes.length);
                    for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
                    const blob = new Blob([arr], { type: data.content_type || 'text/csv' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = data.filename || `export-${jobId}.csv`;
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                })
                .catch(err => alert("Download failed: " + err));
        }

        document.getElementById('export-form').onsubmit = async (e) => {
            e.preventDefault();
            const btn = e.submitter;
            btn.disabled = true;
            btn.textContent = "Scheduling...";

            try {
                const response = await fetch(API_URL_JOBS, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({
                        "_func": "create_job",
                        "job_type": "EXPORT",
                        "subtype": "ADMIN_LOGS",
                        "start_date": document.getElementById('export-start-date').value,
                        "end_date": document.getElementById('export-end-date').value,
                        "fiduciary_id": FIDUCIARY_ID
                    })
                });

                if (response.ok) {
                    alert("Export job queued successfully. Check 'View Downloads' for progress.");
                    closeModals();
                    openDownloadsModal();
                } else { alert("Failed to schedule export."); }
            } catch (err) { alert("Network error."); }
            finally { btn.disabled = false; btn.textContent = "Queue Export Job"; }
        };

        function handleLogout() {
            localStorage.clear();
            window.location.href = "../index.html";
        }

        document.addEventListener('DOMContentLoaded', () => {
            auditActivityBody = document.getElementById('audit-activity-body');
            auditErrorMessageP = document.getElementById('audit-error-message');
            document.getElementById('username').textContent = USER_NAME;

            document.getElementById('menu-toggle').addEventListener('click', toggleMenu);
            document.getElementById('sidebar-backdrop').addEventListener('click', toggleMenu);

            loadDashboardMetrics();
            loadRecentAuditActivity();
        });
