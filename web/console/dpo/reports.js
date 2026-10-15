// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
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

        const API_URL_JOBS = '/api/v1/admin/job';
        const FIDUCIARY_ID = localStorage.getItem('fiduciary_id') || 'fiduciary_hub_abc';
        const AUTH_TOKEN = localStorage.getItem('authToken');
        if (localStorage.getItem('role') === 'OPERATOR') {
            document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
        }
        const USER_NAME = localStorage.getItem('username');
        document.getElementById('username').textContent = USER_NAME || 'DPO User';
        // --- Core Functions ---

        async function loadJobs() {
            const tbody = document.getElementById('job-table-body');
            try {
                const response = await fetch(API_URL_JOBS, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ "_func": "list_jobs", "fiduciary_id": FIDUCIARY_ID, "job_type": "EXPORT"})
                });

                if (response.ok) {
                    const jobs = await response.json();

                    if (jobs.status === 401) {
                        alert("Session Expired: " + (jobs.message || "Authentication required."));
                        handleLogout();
                        return;
                    }

                    renderJobTable(jobs.data || jobs);
                }
            } catch (e) { console.error("Failed to load background jobs", e); }
        }

        function renderJobTable(jobs) {
            const tbody = document.getElementById('job-table-body');
            if (!jobs || jobs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="py-10 text-center text-slate-400 italic">No background tasks found.</td></tr>';
                return;
            }

            tbody.innerHTML = jobs.map(job => {
                const statusColor = getStatusColor(job.status);
                const isComplete = job.status === 'COMPLETED';

                return `
                    <tr class="hover:bg-slate-50/50 transition-colors">
                        <td class="py-4 px-2 font-mono text-[11px] text-slate-500">...${esc(job.id.slice(-12))}</td>
                        <td class="py-4 px-2 font-bold text-slate-700">${esc(job.subtype)}</td>
                        <td class="py-4 px-2 text-slate-500">${esc(new Date(job.created_at).toLocaleString())}</td>
                        <td class="py-4 px-2">
                            <span class="status-pill ${statusColor}">${esc(job.status)}</span>
                        </td>
                        <td class="py-4 px-2 text-right">
                            ${isComplete
                                ? `<button data-jid="${esc(job.id)}" class="dl-btn text-teal-600 font-bold hover:underline flex items-center justify-end gap-1 ml-auto">
                                     <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                                     Download CSV
                                   </button>`
                                : `<span class="text-slate-300 italic text-[11px]">Preparing...</span>`}
                        </td>
                    </tr>
                `;
            }).join('');
            tbody.querySelectorAll('.dl-btn').forEach(btn => {
                btn.addEventListener('click', () => downloadFile(btn.dataset.jid));
            });
        }

        function getStatusColor(status) {
            switch (status) {
                case 'PENDING': return 'bg-slate-100 text-slate-600';
                case 'RUNNING': return 'bg-amber-100 text-amber-700 animate-pulse';
                case 'COMPLETED': return 'bg-green-100 text-green-700';
                case 'FAILED': return 'bg-red-100 text-red-700';
                default: return 'bg-gray-100 text-gray-500';
            }
        }

        // --- Action Handlers ---

        document.getElementById('job-form').onsubmit = async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submit-job-btn');
            btn.disabled = true;
            btn.innerHTML = `<svg class="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Scheduling...`;

            const payload = {
                "_func": "create_job",
                "job_type": "EXPORT",
                "subtype": document.getElementById('export-subtype').value,
                "start_date": document.getElementById('start-date').value,
                "end_date": document.getElementById('end-date').value,
                "fiduciary_id": FIDUCIARY_ID
            };

            try {
                const response = await fetch(API_URL_JOBS, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    alert("Export Job successfully added to the queue. Artifact will be ready for review once completed.");
                    loadJobs();
                } else {
                    alert("Failed to initiate export. Check system logs.");
                }
            } catch (err) {
                alert("Network error: Backend registry not responding.");
            } finally {
                btn.disabled = false;
                btn.innerHTML = `Initiate Export`;
            }
        };

        async function downloadFile(jobId) {
            // P6-03: the ?auth= query parameter was removed (SEC-17) and a browser
            // navigation cannot set an Authorization header, so the file is fetched
            // through the authenticated API and given to the browser as a blob.
            try {
                const res = await fetch(API_URL_JOBS, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ "_func": "download_file", "job_id": jobId })
                });
                const data = await res.json();
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
            } catch (err) { alert("Download failed: " + err); }
        }

        function handleLogout() {
          localStorage.removeItem('authToken');
          localStorage.removeItem('username');
          window.location.href = "../index.html";
        }

        // --- Init ---
        window.onload = () => {
            loadJobs();
            // Poll for status updates every 30 seconds
            setInterval(loadJobs, 30000);
        };
