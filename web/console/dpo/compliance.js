// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's controls carry data-action / data-change-action and are wired here. Clicks go
// through one delegated listener, so controls rendered later (reveal) are served too.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        openCesJobsModal: () => openCesJobsModal(),
        openNewCesJobModal: () => openNewCesJobModal(),
        closeModal: (el) => closeModal(el.getAttribute('data-arg')),
        closeCesJobsModal: () => { closeModal('ces-jobs-modal'); loadPurgeRequests(); },
        loadCesJobs: () => loadCesJobs(),
        revealPurgeRow: (el) => revealInto(el, 'purge_request', el.getAttribute('data-id'), el.previousElementSibling),
        revealPurgeDetail: (el) => revealInto(el, 'purge_request', updateForm.getAttribute('data-id'), document.getElementById('detail-user-id')),
    };
    document.addEventListener('click', (e) => {
        const el = e.target.closest('[data-action]');
        const fn = el && clickHandlers[el.getAttribute('data-action')];
        if (fn) fn(el, e);
    });
    const changeHandlers = {
        togglePrincipalInput: (el) => togglePrincipalInput(el.getAttribute('data-arg') === 'true'),
    };
    document.querySelectorAll('[data-change-action]').forEach((el) => {
        const fn = changeHandlers[el.getAttribute('data-change-action')];
        if (fn) el.addEventListener('change', (e) => fn(el, e));
    });
})();

    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    // --- Configuration ---
    const API_URL_PURGE = '/api/v1/admin/compliance';
    const API_URL_JOBS = '/api/v1/admin/job';
    const API_URL_OPERATOR = '/api/v1/admin/operator';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    const IS_OPERATOR = localStorage.getItem('role') === 'OPERATOR';
    if (IS_OPERATOR) {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
        document.getElementById('run-compliance-check-btn').remove();
        document.getElementById('assignment-section').remove();
    }
    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'DPO User';

    // --- Logged reveal (reveal_user_id) ---
    // Console reads carry masked principal identifiers. A DPO or administrator sees one in
    // the clear only through reveal_user_id, which writes an audit row before answering and
    // allows 20 reveals a minute. A revealed value lives only in the page (re-masked after
    // REMASK_MS) and is never written to localStorage.
    const API_URL_PII = '/api/v1/admin/pii';
    const REVEAL_LABEL = 'Reveal — this action is logged';
    const REMASK_MS = 30000;
    const CAN_REVEAL = ['DPO', 'ADMIN'].includes(String(localStorage.getItem('role') || '').toUpperCase());
    let revealConfirmed = false;

    function revealButton(action, id) {
        if (!CAN_REVEAL) return null;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'reveal-btn block text-[10px] text-amber-700 hover:text-amber-900 underline';
        btn.textContent = REVEAL_LABEL;
        btn.setAttribute('data-action', action);
        if (id) btn.setAttribute('data-id', id);
        return btn;
    }

    // The revealed fields, or null (declined, refused or failed: the reason is shown).
    async function revealFields(source, id) {
        if (!CAN_REVEAL || !id) return null;
        if (!revealConfirmed) {
            if (!confirm("This reveal will be recorded in the audit log against your account. Continue?")) return null;
            revealConfirmed = true;
        }
        let response, body = {};
        try {
            response = await fetch(API_URL_PII, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "reveal_user_id", "source": source, "id": id, "fiduciary_id": localStorage.getItem('fiduciary_id') })
            });
            try { body = await response.json(); } catch (e) { body = {}; }
        } catch (e) {
            alert("Reveal failed: the server could not be reached.");
            return null;
        }
        if (response.status === 429) {
            alert("Too many reveals: you may reveal at most 20 values a minute. Wait a minute, then try again.");
            return null;
        }
        if (response.status === 403) {
            alert("You do not have permission to reveal this value. Only a DPO or an administrator may.");
            return null;
        }
        if (!response.ok) {
            alert("Reveal failed: " + (body.message || `status ${response.status}`));
            return null;
        }
        return body.fields || {};
    }

    // Reveals the principal of `source` record `id` into `target` in place of its masked
    // text, then masks it again (unless the element has since been re-rendered).
    async function revealInto(btn, source, id, target) {
        btn.disabled = true;
        const fields = await revealFields(source, id);
        if (!fields || !target) { btn.disabled = false; return; }
        const original = target.textContent;
        target.textContent = fields.user_id || 'N/A';
        const shown = target.textContent;
        setTimeout(() => {
            if (target.textContent === shown) target.textContent = original;
            btn.disabled = false;
        }, REMASK_MS);
    }

    // Map of operator_id -> display name, used for the "Assigned To" column/dropdown.
    // Operators can't delegate, so they never need this lookup.
    let OperatorMap = {};
    async function fetchOperators() {
        if (IS_OPERATOR) return;
        try {
            const response = await fetch(API_URL_OPERATOR, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_users" })
            });
            const users = await response.json();
            if (Array.isArray(users)) {
                users.filter(u => u.role === 'OPERATOR').forEach(u => { OperatorMap[u.user_id] = u.username; });
            }
        } catch (e) { console.error("Failed to load operators", e); }
    }

    let tableBody, countSpan, searchInput, statusFilter, purgeModalOverlay, updateForm;

    function toggleMenu() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebar-backdrop').classList.toggle('hidden');
    }

    function closeModal(modalId) {
        if(modalId) {
            document.getElementById(modalId).style.display = 'none';
        } else {
             // Fallback for older calls
             document.querySelectorAll('.modal-overlay').forEach(m => m.style.display = 'none');
        }
    }

    function createStatusBadge(status) {
        let colorClass = '';
        switch (status) {
            case 'PURGE_INITIATED': colorClass = 'bg-blue-100 text-blue-800'; break;
            case 'PURGE_IN_PROGRESS': colorClass = 'bg-yellow-100 text-yellow-800'; break;
            case 'PURGE_COMPLETED': colorClass = 'bg-green-100 text-green-800'; break;
            case 'PURGE_FAILED': colorClass = 'bg-red-100 text-red-800'; break;
            // Updated color for Legal Hold as requested
            case 'LEGAL_HOLD_APPLIED': colorClass = 'bg-orange-100 text-orange-800'; break;
            default: colorClass = 'bg-gray-100 text-gray-800';
        }
        return `<span class="px-3 py-1 text-xs font-medium rounded-full ${colorClass}">${esc(String(status || '').replace(/_/g, ' '))}</span>`;
    }

    function createRequestRow(req) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="px-2 py-2 font-mono text-gray-600 truncate" title="${esc(req.id)}">...${esc(String(req.id).slice(-8))}</td>
            <td class="px-2 py-2 text-gray-800"><span class="principal-id block truncate"></span></td>
            <td class="px-2 py-2 text-gray-800 truncate" title="${esc(req.purpose_id)}">${esc(req.purpose_id)}</td>
            <td class="px-2 py-2 text-gray-600 truncate" title="${esc(req.trigger_event)}">${esc(req.trigger_event)}</td>
            <td class="px-2 py-2 text-gray-600 truncate" title="${esc(req.app_name)}">${esc(req.app_name)}</td>
            <td class="px-2 py-2 text-gray-600 truncate">${esc(new Date(req.initiated_at).toLocaleDateString())}</td>
            <td class="px-2 py-2 truncate">${createStatusBadge(req.status)}</td>
            <td class="px-2 py-2 text-gray-600 truncate">${esc(OperatorMap[req.assigned_operator_id] || 'Unassigned')}</td>
            <td class="px-2 py-2">
                <button class="manage-purge-btn text-indigo-600 hover:text-indigo-900 font-medium" data-id="${esc(req.id)}">Manage</button>
            </td>
        `;
        row.querySelector('.manage-purge-btn').addEventListener('click', () => viewPurgeRequest(req.id));
        const idSpan = row.querySelector('.principal-id');
        idSpan.textContent = req.user_id || 'N/A';
        idSpan.title = req.user_id || '';
        const reveal = revealButton('revealPurgeRow', req.id);
        if (reveal) idSpan.after(reveal);
        return row;
    }

    async function loadPurgeRequests() {
        tableBody.innerHTML = `<tr><td colspan="9" class="p-4 text-center text-gray-500">Loading requests...</td></tr>`;

        try {
            const payload = {
                "_func": "list_purge_requests",
                "fiduciary_id": localStorage.getItem('fiduciary_id'),
                "search": searchInput.value,
                "status": statusFilter.value === 'ALL' ? '' : statusFilter.value
            };

            const response = await fetch(API_URL_PURGE, {
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
            const requests = data || [];

            tableBody.innerHTML = '';
            if (requests.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="9" class="p-4 text-center text-gray-500">No matching requests found.</td></tr>`;
            } else {
                requests.forEach(r => tableBody.appendChild(createRequestRow(r)));
            }
            countSpan.textContent = `Total: ${requests.length} Requests`;

        } catch (error) {
            tableBody.innerHTML = `<tr><td colspan="9" class="p-4 text-center text-red-600">Failed to load compliance data.</td></tr>`;
        }
    }

    async function viewPurgeRequest(id) {
        try {
            const response = await fetch(API_URL_PURGE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_purge_request", "id": id, "fiduciary_id": localStorage.getItem('fiduciary_id')})
            });
            const req = await response.json();

            document.getElementById('modal-app-name').textContent = req.app_name;
            document.getElementById('detail-user-id').textContent = req.user_id || 'N/A';
            document.getElementById('detail-reveal-btn').disabled = false;
            document.getElementById('detail-purpose-id').textContent = req.purpose_id;
            document.getElementById('detail-trigger').textContent = req.trigger_event;
            document.getElementById('detail-status').innerHTML = createStatusBadge(req.status);
            document.getElementById('detail-initiated').textContent = new Date(req.initiated_at).toLocaleString();
            document.getElementById('detail-context').textContent = req.details || "No additional context provided.";
            // Prefill form
            document.getElementById('new-status').value = req.status === 'PENDING' ? 'IN_PROGRESS' : req.status;
            document.getElementById('details-notes').value = req.details || '';

            // Assignment Setup (DPO/ADMIN only -- Operators can't delegate)
            if (!IS_OPERATOR) {
                const assignSelect = document.getElementById('assign-operator-select');
                assignSelect.innerHTML = '<option value="">Unassigned</option>' +
                    Object.entries(OperatorMap).map(([opId, name]) => `<option value="${esc(opId)}">${esc(name)}</option>`).join('');
                assignSelect.value = req.assigned_operator_id || '';
                document.getElementById('assign-operator-btn').setAttribute('data-id', id);
            }

            updateForm.setAttribute('data-id', id);
            purgeModalOverlay.style.display = 'flex';
        } catch (e) { alert("Error fetching request details."); }
    }

    // --- CES JOB LOGIC ---

    function openCesJobsModal() {
        document.getElementById('ces-jobs-modal').style.display = 'flex';
        loadCesJobs();
    }

    function openNewCesJobModal() {
        document.getElementById('new-ces-job-modal').style.display = 'flex';
    }

    function togglePrincipalInput(show) {
        const container = document.getElementById('principal-input-container');
        if (show) container.classList.remove('hidden');
        else container.classList.add('hidden');
    }

    async function loadCesJobs() {
        const tbody = document.getElementById('ces-jobs-body');
        tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-400">Loading jobs...</td></tr>';

        try {
            const response = await fetch(API_URL_JOBS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_jobs", "fiduciary_id": FIDUCIARY_ID, "job_type":"CES" })
            });

            const data = await response.json();
            const cesJobs = data.slice(0, 10);

            tbody.innerHTML = '';
            if (cesJobs.length === 0) {
                 tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-400">No background enforcement jobs found.</td></tr>';
            } else {
                cesJobs.forEach(job => {
                     const statusColor = job.status === 'PURGE_COMPLETED' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-600';
                     tbody.innerHTML += `
                        <tr class="hover:bg-slate-50 border-b border-slate-50">
                            <td class="p-3 font-mono text-[11px] text-slate-500">...${esc(String(job.id).slice(-8))}</td>
                            <td class="p-3 font-bold text-xs text-slate-700">${esc(job.job_type)}</td>
                            <td class="p-3 text-xs text-slate-600">${esc(job.subtype || 'FULL_RUN')}</td>
                            <td class="p-3 text-xs text-slate-500">${esc(new Date(job.created_at).toLocaleString())}</td>
                            <td class="p-3"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${statusColor}">${esc(job.status)}</span></td>
                        </tr>
                     `;
                });
            }
        } catch (e) {
            console.error("Failed to load CES jobs", e);
        }
    }

    document.getElementById('new-ces-job-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const scope = document.querySelector('input[name="ces_scope"]:checked').value;
        let subtype = "FULL";

        if (scope === 'PRINCIPAL') {
            const pid = document.getElementById('target-principal-id').value.trim();
            if (!pid) return alert("Please enter a Target User ID.");
            subtype = `${pid}`;
        }

        const btn = document.getElementById('start-ces-btn');
        btn.disabled = true;
        btn.textContent = "Scheduling...";

        try {
            const payload = {
                "_func": "create_job",
                "job_type": "CES",
                "subtype": subtype,
                "fiduciary_id": FIDUCIARY_ID
            };

            const response = await fetch(API_URL_JOBS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                alert("Compliance Enforcement Job Initiated.");
                closeModal('new-ces-job-modal');
                openCesJobsModal(); // Switch to view jobs
            } else {
                alert("Failed to schedule job.");
            }
        } catch(err) {
            alert("Network Error.");
        } finally {
            btn.disabled = false;
            btn.textContent = "Start Engine";
        }
    });


    // --- Init ---
    tableBody = document.getElementById('purge-table-body');
    countSpan = document.getElementById('request-count');
    searchInput = document.getElementById('search-input');
    statusFilter = document.getElementById('status-filter');
    purgeModalOverlay = document.getElementById('purge-modal-overlay');
    updateForm = document.getElementById('purge-update-form');
    if (CAN_REVEAL) document.getElementById('detail-reveal-btn').classList.remove('hidden');

    document.getElementById('menu-toggle').addEventListener('click', toggleMenu);
    document.getElementById('sidebar-backdrop').addEventListener('click', toggleMenu);
    statusFilter.addEventListener('change', loadPurgeRequests);
    searchInput.addEventListener('input', () => { loadPurgeRequests(); });

    if (!IS_OPERATOR) {
        document.getElementById('assign-operator-btn').addEventListener('click', async function() {
            const btn = this;
            const id = btn.getAttribute('data-id');
            const operatorId = document.getElementById('assign-operator-select').value;
            if (!operatorId) {
                alert("Select an Operator to assign.");
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Assigning...';
            try {
                const response = await fetch(API_URL_PURGE, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ "_func": "assign_purge_request", "id": id, "operator_id": operatorId, "fiduciary_id": localStorage.getItem('fiduciary_id') })
                });
                if (response.ok) {
                    alert("Purge request assigned.");
                    loadPurgeRequests();
                } else {
                    const errorMsg = (await response.json()).message || `Status: ${response.status}`;
                    alert(`Failed to assign: ${errorMsg}`);
                }
            } catch (err) {
                alert("Network error while assigning.");
            } finally {
                btn.disabled = false;
                btn.textContent = 'Assign';
            }
        });
    }

    updateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = updateForm.getAttribute('data-id');
        const btn = document.getElementById('update-request-btn');
        btn.disabled = true;
        btn.textContent = 'Saving...';

        try {
            const payload = {
                "_func": "update_purge_status",
                "fiduciary_id": localStorage.getItem('fiduciary_id'),
                "id": id,
                "status": document.getElementById('new-status').value,
                "details": document.getElementById('details-notes').value
            };

            const response = await fetch(API_URL_PURGE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                alert("Purge request status updated successfully.");
                closeModal('purge-modal-overlay');
                loadPurgeRequests();
            } else {
                alert("Failed to update status.");
            }
        } finally {
            btn.disabled = false;
            btn.textContent = 'Save Fulfillment State';
        }
    });

    fetchOperators().then(loadPurgeRequests);

    window.viewPurgeRequest = viewPurgeRequest;
    window.closeModal = closeModal;
    window.openCesJobsModal = openCesJobsModal;
    window.openNewCesJobModal = openNewCesJobModal;
    window.togglePrincipalInput = togglePrincipalInput;
    window.loadCesJobs = loadCesJobs;
    window.handleLogout = () => { localStorage.clear(); window.location.href = "../index.html"; };
