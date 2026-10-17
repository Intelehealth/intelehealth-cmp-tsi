// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's controls carry data-action / data-change-action and are wired here. Clicks go
// through one delegated listener, so controls rendered later (reveal) are served too.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        openLogGrievance: () => openLogGrievance(),
        closeLogGrievance: () => closeLogGrievance(),
        revealGrievanceRow: (el) => revealInto(el, 'grievance', el.getAttribute('data-id'), el.previousElementSibling),
        revealGrievanceDetail: (el) => revealInto(el, 'grievance', resolutionForm.getAttribute('data-grievance-id'), document.getElementById('detail-user-id')),
    };
    document.addEventListener('click', (e) => {
        const el = e.target.closest('[data-action]');
        const fn = el && clickHandlers[el.getAttribute('data-action')];
        if (fn) fn(el, e);
    });
})();

    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    // --- Configuration ---
    const API_URL_GRIEVANCE = '/api/v1/grievance'; // Endpoint for Grievance CRUD
    const API_URL_FIDUCIARIES_LIST = '/api/v1/admin/fiduciary';
    const API_URL_OPERATOR = '/api/v1/admin/operator';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const IS_OPERATOR = localStorage.getItem('role') === 'OPERATOR';
    if (IS_OPERATOR) {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
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

    // --- Global DOM Element Variables ---
    let sidebar, menuToggle, backdrop, grievanceModalOverlay, tableBody, countSpan, errorMessageP, searchInput, statusFilter;
    let modalGrievanceId, detailType, detailUserId, detailDate, detailAssigned, detailStatus, detailDeadline, detailFiduciary, detailDescription;
    let resolutionForm, newStatusSelect, resolutionDetailsInput;
    let FiduciaryList = {}; // Cache Fiduciary names

    // --- Helper Functions ---

    function toggleMenu() {
        sidebar.classList.toggle('open');
        backdrop.classList.toggle('hidden');
    }

    function closeModal() {
        grievanceModalOverlay.style.display = 'none';
        loadGrievances(); // Reload list after resolution attempt
    }

    function getFiduciaryName(id) {
        if (!id) return 'N/A';
        const fiduciary = FiduciaryList[id];
        return fiduciary ? fiduciary.name : `Fiduciary ID: ${id}`;
    }

    function createStatusBadge(status) {
        let colorClass = '';
        switch (status) {
            case 'NEW': colorClass = 'bg-blue-100 text-blue-800'; break;
            case 'IN_PROGRESS': colorClass = 'bg-yellow-100 text-yellow-800'; break;
            case 'RESOLVED': colorClass = 'bg-green-100 text-green-800'; break;
            case 'OVERDUE':
            case 'ESCALATED': colorClass = 'bg-red-100 text-red-800'; break;
            default: colorClass = 'bg-gray-100 text-gray-800';
        }
        return `<span class="px-3 py-1 text-xs font-medium rounded-full ${colorClass}">${esc(String(status || '').replace(/_/g, ' '))}</span>`;
    }

    function createChannelBadge(channel) {
        const value = channel || 'PORTAL';
        const colorClass = value === 'PORTAL' ? 'bg-gray-100 text-gray-800' : 'bg-purple-100 text-purple-800';
        return `<span class="px-3 py-1 text-xs font-medium rounded-full ${colorClass}">${esc(value.replace(/_/g, ' '))}</span>`;
    }

    function calculateDeadlineDisplay(deadline,status) {
        if (!deadline) return 'N/A';
        const now = new Date();
        const due = new Date(deadline);
        const diffTime = due.getTime() - now.getTime();
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays < 0) return `<span class="text-red-600 font-bold">${Math.abs(diffDays)} Days Overdue</span>`;
        if (diffDays <= 5) return `<span class="text-orange-600 font-bold">${diffDays} Days Left</span>`;
        return `${diffDays} Days Left`;
    }

    function createGrievanceRow(grievance) {
        const row = document.createElement('tr');

        const isOverdue = new Date(grievance.due_date) < new Date() && grievance.status !== 'RESOLVED' && grievance.status !== 'CLOSED';
        const status = isOverdue ? 'OVERDUE' : grievance.status;

        row.innerHTML = `
            <td class="px-4 py-3 text-sm text-gray-600">...${esc(grievance.grievance_id.slice(-8))}</td>
            <td class="px-4 py-3 text-sm font-mono text-gray-700"><span class="principal-id"></span></td>
            <td class="px-4 py-3 text-sm font-medium text-gray-900">${esc(grievance.type.replace(/_/g, ' '))}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${createChannelBadge(grievance.channel)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(grievance.subject || 'N/A')}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(new Date(grievance.submission_timestamp).toLocaleDateString())}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm">${createStatusBadge(status)}</td>
            <td class="px-4 py-3 text-sm font-semibold">${calculateDeadlineDisplay(grievance.due_date,status)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(OperatorMap[grievance.assigned_dpo_user_id] || 'Unassigned')}</td>
            <td class="px-4 py-3 text-sm">
                <button class="view-grievance-btn text-indigo-600 hover:text-indigo-900 font-medium text-sm" data-grievance-id="${esc(grievance.grievance_id)}">View/Manage</button>
            </td>
        `;
        row.querySelector('.view-grievance-btn').addEventListener('click', () => viewGrievance(grievance.grievance_id));
        const idSpan = row.querySelector('.principal-id');
        idSpan.textContent = grievance.user_id || 'N/A';
        const reveal = revealButton('revealGrievanceRow', grievance.grievance_id);
        if (reveal) idSpan.after(reveal);
        return row;
    }

    // --- Core Logic ---

    // Fetch Fiduciaries and populate cache
    async function fetchFiduciaries() {
        try {
            const payload = {"_func": "list_fiduciaries"};
            const response = await fetch(API_URL_FIDUCIARIES_LIST, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const responseData = await response.json();

                if (responseData.status === 401) {
                    alert("Auth Failed: " + (responseData.message || "Authentication required."));
                    handleLogout();
                    return;
                }

                const fiduciaries = responseData.data || responseData;
                FiduciaryList = {};
                fiduciaries.forEach(f => {
                    FiduciaryList[f.fiduciary_id] = f;
                });
            }
        } catch (error) {
            console.error("Warning: Failed to fetch Fiduciaries for naming in Grievance List.", error);
        }
    }


    async function loadGrievances(searchTerm = "") {
        tableBody.innerHTML = `<tr><td colspan="10" class="p-4 text-center text-gray-500">Loading Grievance data...</td></tr>`;
        errorMessageP.classList.add('hidden');

        try {
            const listPayload = {
                "_func": "list_grievances",
                // list_grievances matches the whole principal id (through its HMAC) and an exact status.
                "user_id": searchTerm,
                "status": statusFilter.value === 'ALL' ? '' : statusFilter.value,
                "sort_by": "SUBMISSION_DATE_DESC",
                "fiduciary_id":localStorage.getItem("fiduciary_id"),
                "page": 1,
                "limit": 50
            };

            const response = await fetch(API_URL_GRIEVANCE, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${AUTH_TOKEN}`
                },
                body: JSON.stringify(listPayload)
            });

            if (!response.ok) {
                throw new Error(`API returned status ${response.status}`);
            }

            const responseData = await response.json();

             if (responseData.status === 401) {
                alert("Session Expired: " + (responseData.message || "Authentication required."));
                handleLogout();
                return;
            }
            const grievances = responseData.data || responseData;

            if (Array.isArray(grievances)) {
                tableBody.innerHTML = '';

                if (grievances.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="10" class="p-4 text-center text-gray-500">No grievances found matching criteria.</td></tr>`;
                } else {
                    grievances.forEach(g => {
                        tableBody.appendChild(createGrievanceRow(g));
                    });
                    countSpan.textContent = `Showing 1 - ${grievances.length} of ${grievances.length} Total`;
                }
            } else {
                throw new Error(responseData.message || 'API returned unexpected structure.');
            }

        } catch (error) {
            console.error("Error loading Grievances:", error);
            tableBody.innerHTML = `<tr><td colspan="10" class="p-4 text-center text-red-600">
                Error connecting to the Grievance API.
            </td></tr>`;
            errorMessageP.classList.remove('hidden');
            countSpan.textContent = '0 Total';
        }
    }

    // Function to fetch a single Grievance record
    async function fetchGrievanceDetails(grievanceId) {
        try {
            const payload = { "_func": "get_grievance", "grievance_id": grievanceId, "fiduciary_id": localStorage.getItem('fiduciary_id')};
            console.log(payload);

            const response = await fetch(API_URL_GRIEVANCE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error(`Failed to fetch details for grievance ${grievanceId}. Status: ${response.status}`);

            const responseData = await response.json();

            if (responseData.grievance_id) {
                return responseData;
            } else {
                throw new Error(responseData.message || 'Grievance details not found.');
            }
        } catch (error) {
            console.error("Error fetching Grievance details:", error);
            alert(`Failed to load grievance details: ${error.message}`);
            return null;
        }
    }

    // Function to populate and show modal
    async function viewGrievance(id) {
        const grievance = await fetchGrievanceDetails(id);
        if (!grievance) return;

        grievanceModalOverlay.style.display = 'flex';

        // Populate modal details
        document.getElementById('modal-grievance-id').textContent = grievance.id;
        document.getElementById('detail-channel').innerHTML = createChannelBadge(grievance.channel);
        document.getElementById('detail-user-id').textContent = grievance.user_id || 'N/A';
        document.getElementById('detail-reveal-btn').disabled = false;
        document.getElementById('detail-date').textContent = new Date(grievance.submission_timestamp).toLocaleString();
        document.getElementById('detail-status').innerHTML = createStatusBadge(grievance.status);
        document.getElementById('detail-deadline').textContent = new Date(grievance.due_date).toLocaleDateString();
        document.getElementById('detail-description').textContent = grievance.description;

        // Resolution Form Setup
        resolutionForm.setAttribute('data-grievance-id', grievance.grievance_id);
        resolutionForm.setAttribute('fiduciary-id', grievance.fiduciary_id);
        newStatusSelect.value = grievance.status; // Set current status

        // Assignment Setup (DPO/ADMIN only -- Operators can't delegate)
        if (!IS_OPERATOR) {
            const assignSelect = document.getElementById('assign-operator-select');
            assignSelect.innerHTML = '<option value="">Unassigned</option>' +
                Object.entries(OperatorMap).map(([id, name]) => `<option value="${esc(id)}">${esc(name)}</option>`).join('');
            assignSelect.value = grievance.assigned_dpo_user_id || '';
            document.getElementById('assign-operator-btn').setAttribute('data-grievance-id', grievance.grievance_id);
        }

        // Attachments (GR-04)
        document.getElementById('upload-attachment-btn').setAttribute('data-grievance-id', grievance.grievance_id);
        document.getElementById('attachment-file-input').value = '';
        renderAttachments(grievance.attachments);
    }

    // --- Grievance Attachments (GR-04 / D15) ---
    const ATTACHMENT_TYPES = ['application/pdf', 'image/png', 'image/jpeg', 'text/plain'];

    function parseAttachments(raw) {
        if (!raw) return [];
        if (typeof raw === 'string') {
            try { raw = JSON.parse(raw); } catch (e) { return []; }
        }
        return Array.isArray(raw) ? raw : [];
    }

    function formatBytes(n) {
        const b = Number(n) || 0;
        if (b < 1024) return `${b} B`;
        if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
        return `${(b / (1024 * 1024)).toFixed(1)} MB`;
    }

    function renderAttachments(raw) {
        const list = document.getElementById('attachment-list');
        const attachments = parseAttachments(raw);
        if (attachments.length === 0) {
            list.innerHTML = '<li class="text-gray-500">No attachments.</li>';
            return;
        }
        list.innerHTML = attachments.map(a => `
            <li class="flex items-center justify-between gap-3 p-2 bg-gray-50 rounded-md">
                <span class="truncate" title="SHA-256: ${esc(a.sha256)}">${esc(a.file_name)} <span class="text-gray-500">(${esc(formatBytes(a.size_bytes))})</span></span>
                <button type="button" class="download-attachment-btn text-indigo-600 hover:text-indigo-900 font-medium text-sm" data-attachment-id="${esc(a.attachment_id)}">Download</button>
            </li>
        `).join('');
        list.querySelectorAll('.download-attachment-btn').forEach(btn => {
            btn.addEventListener('click', () => downloadAttachment(btn.getAttribute('data-attachment-id'), btn));
        });
    }

    async function downloadAttachment(attachmentId, btn) {
        btn.disabled = true;
        try {
            const response = await fetch(API_URL_GRIEVANCE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_grievance_attachment", "attachment_id": attachmentId })
            });
            const data = await response.json();
            if (!response.ok || !data.content_base64) {
                throw new Error(data.message || `Status: ${response.status}`);
            }
            const binary = atob(data.content_base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            const blob = new Blob([bytes], { type: data.content_type || 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = data.file_name || 'attachment';
            document.body.appendChild(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (error) {
            console.error("Error downloading attachment:", error);
            alert(`Failed to download attachment: ${error.message}`);
        } finally {
            btn.disabled = false;
        }
    }

    function readFileAsBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => {
                const result = String(reader.result || '');
                const comma = result.indexOf(',');
                resolve(comma >= 0 ? result.slice(comma + 1) : result);
            };
            reader.onerror = () => reject(reader.error || new Error('Could not read file.'));
            reader.readAsDataURL(file);
        });
    }

    async function uploadAttachment() {
        const btn = document.getElementById('upload-attachment-btn');
        const input = document.getElementById('attachment-file-input');
        const grievanceId = btn.getAttribute('data-grievance-id');
        const file = input.files && input.files[0];
        if (!grievanceId) return;
        if (!file) {
            alert("Choose a file to upload.");
            return;
        }
        if (!ATTACHMENT_TYPES.includes(file.type)) {
            alert("Only PDF, PNG, JPEG or plain text files can be attached.");
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Uploading...';
        try {
            const contentBase64 = await readFileAsBase64(file);
            const response = await fetch(API_URL_GRIEVANCE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({
                    "_func": "upload_grievance_attachment",
                    "grievance_id": grievanceId,
                    "file_name": file.name.slice(0, 255),
                    "content_type": file.type,
                    "content_base64": contentBase64
                })
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.message || `Status: ${response.status}`);
            }
            input.value = '';
            const refreshed = await fetchGrievanceDetails(grievanceId);
            if (refreshed) renderAttachments(refreshed.attachments);
        } catch (error) {
            console.error("Error uploading attachment:", error);
            alert(`Failed to upload attachment: ${error.message}`);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Upload';
        }
    }

     function handleLogout() {
      localStorage.removeItem('authToken');
      localStorage.removeItem('username');
      window.location.href = "../index.html";
    }

    // --- Event Listeners and Initialization ---


    // --- Variable Assignments ---
    sidebar = document.getElementById('sidebar');
    menuToggle = document.getElementById('menu-toggle');
    backdrop = document.getElementById('sidebar-backdrop');
    tableBody = document.getElementById('grievance-table-body');
    countSpan = document.getElementById('grievance-count');
    errorMessageP = document.getElementById('grievance-error-message');
    searchInput = document.getElementById('search-input');
    statusFilter = document.getElementById('status-filter');

    grievanceModalOverlay = document.getElementById('grievance-modal-overlay');
    resolutionForm = document.getElementById('resolution-form');
    newStatusSelect = document.getElementById('new-status');
    resolutionDetailsInput = document.getElementById('resolution-details');

    // Detail Spans
    modalGrievanceId = document.getElementById('modal-grievance-id');
    detailType = document.getElementById('detail-type');
    detailUserId = document.getElementById('detail-user-id');
    detailDate = document.getElementById('detail-date');
    detailAssigned = document.getElementById('detail-assigned');
    detailStatus = document.getElementById('detail-status');
    detailDeadline = document.getElementById('detail-deadline');
    detailFiduciary = document.getElementById('detail-fiduciary');
    detailDescription = document.getElementById('detail-description');


    if (IS_OPERATOR) {
        document.getElementById('assignment-section').remove();
    }
    if (CAN_REVEAL) document.getElementById('detail-reveal-btn').classList.remove('hidden');

    // --- Fetch Operators, Fiduciaries and Load Grievances ---
    fetchOperators().then(loadGrievances);

    // --- Event Listener Attachments ---
    menuToggle.addEventListener('click', toggleMenu);
    backdrop.addEventListener('click', toggleMenu);

    // Filters
    statusFilter.addEventListener('change', () => loadGrievances(searchInput.value.trim()));

    // Search
    searchInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            loadGrievances(searchInput.value.trim());
        }
    });

    // Modal Close
    document.getElementById('close-modal-btn-inner').addEventListener('click', closeModal);

    // Attachment Upload
    document.getElementById('upload-attachment-btn').addEventListener('click', uploadAttachment);

    // --- DPO-logged grievance (Log Grievance) ---
    const logGrievanceModalOverlay = document.getElementById('log-grievance-modal-overlay');
    const logGrievanceForm = document.getElementById('log-grievance-form');
    const logGrievanceError = document.getElementById('log-grievance-error');

    function openLogGrievance() {
        logGrievanceForm.reset();
        logGrievanceError.classList.add('hidden');
        logGrievanceModalOverlay.style.display = 'flex';
    }

    function closeLogGrievance() {
        logGrievanceModalOverlay.style.display = 'none';
    }

    logGrievanceForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        logGrievanceError.classList.add('hidden');

        const payload = {
            "_func": "submit_grievance",
            "user_id": document.getElementById('log-grievance-user-id').value.trim(),
            "fiduciary_id": localStorage.getItem('fiduciary_id'),
            "channel": document.getElementById('log-grievance-channel').value,
            "type": document.getElementById('log-grievance-type').value,
            "subject": document.getElementById('log-grievance-subject').value.trim(),
            "description": document.getElementById('log-grievance-description').value.trim()
        };

        const submitBtn = document.getElementById('log-grievance-submit-btn');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Logging...';

        try {
            const response = await fetch(API_URL_GRIEVANCE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });
            const responseData = await response.json();

            if (response.ok) {
                closeLogGrievance();
                alert(`Grievance logged (Reference: ${responseData.reference_number || responseData.grievance_id}).`);
                loadGrievances(searchInput.value.trim());
            } else {
                logGrievanceError.textContent = responseData.message || `Failed to log grievance (status ${response.status}).`;
                logGrievanceError.classList.remove('hidden');
            }
        } catch (error) {
            logGrievanceError.textContent = "Network error: could not reach the API.";
            logGrievanceError.classList.remove('hidden');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Log Grievance';
        }
    });

    // Handle Operator Assignment (DPO/ADMIN only)
    if (!IS_OPERATOR) {
        document.getElementById('assign-operator-btn').addEventListener('click', async function() {
            const btn = this;
            const grievanceId = btn.getAttribute('data-grievance-id');
            const operatorId = document.getElementById('assign-operator-select').value;
            if (!operatorId) {
                alert("Select an Operator to assign.");
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Assigning...';
            try {
                const response = await fetch(API_URL_GRIEVANCE, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ "_func": "assign_grievance", "grievance_id": grievanceId, "operator_id": operatorId })
                });
                if (response.ok) {
                    alert("Grievance assigned.");
                    loadGrievances(searchInput.value.trim());
                } else {
                    const errorMsg = (await response.json()).message || `Status: ${response.status}`;
                    alert(`Failed to assign: ${errorMsg}`);
                }
            } catch (error) {
                alert("Network error while assigning.");
            } finally {
                btn.disabled = false;
                btn.textContent = 'Assign';
            }
        });
    }

    // Handle Status Update Submission
    resolutionForm.addEventListener('submit', async function(event) {
        event.preventDefault();

        const grievanceId = resolutionForm.getAttribute('data-grievance-id');
        const fiduciaryId = resolutionForm.getAttribute('fiduciary-id');
        const newStatus = newStatusSelect.value;
        const resolutionNotes = resolutionDetailsInput.value;

        if (!grievanceId || !newStatus || !resolutionNotes) {
            alert("Please fill out all resolution fields.");
            return;
        }

        try {
            document.getElementById('update-status-btn').textContent = 'Updating...';
            document.getElementById('update-status-btn').disabled = true;

            const payload = {
                "_func": "update_grievance_status",
                "grievance_id": grievanceId,
                "fiduciary_id": localStorage.getItem('fiduciary_id'),
                "status": newStatus,
                "resolution_details": resolutionNotes
            };

            const response = await fetch(API_URL_GRIEVANCE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                alert(`Grievance ${grievanceId} updated to ${newStatus} successfully.`);
                closeModal();
            } else {
                const errorMsg = (await response.json()).message || `Status: ${response.status}`;
                alert(`Failed to update status: ${errorMsg}`);
            }
        } catch (error) {
            console.error(`Error updating grievance status:`, error);
            alert("Network error: Could not connect to API.");
        } finally {
            document.getElementById('update-status-btn').textContent = 'Update Grievance Status';
            document.getElementById('update-status-btn').disabled = false;
        }
    });


    // Expose functions globally so they can be called by inline onclick attributes
    window.viewGrievance = viewGrievance;
    window.toggleMenu = toggleMenu;
