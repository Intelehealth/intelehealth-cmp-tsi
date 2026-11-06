// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        closeModal: () => closeModal(),
        pickPolicyFile: () => document.getElementById('policy-file-input').click(),
        closeRopaEntryModal: () => closeRopaEntryModal(),
        publishRopaEntryFromModal: () => publishRopaEntryFromModal(),
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
    document.getElementById('policy-file-zone').addEventListener('dragover', (e) => e.preventDefault());
    document.getElementById('policy-file-zone').addEventListener('drop', (e) => handleFileDrop(e));
})();

    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    // --- Configuration ---
    const API_URL_POLICY = '/api/v1/policy';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const IS_OPERATOR = localStorage.getItem('role') === 'OPERATOR';
    if (IS_OPERATOR) {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
        document.getElementById('add-policy-btn').style.display = 'none'; // hidden, not removed: init below still wires the (now invisible) button's onclick
    }

    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'DPO User';

    let timeout; // Debounce
    let tableBody, searchInput, statusFilter, policyModalOverlay, policyForm, errorMessageP;
    let policyIdHidden, policyIdInput, policyJurisdictionSelect;
    let parsedPolicyJson = null;
    // P13-01: policy ids are per tenant; every by-id call names the tenant.
    let editingFiduciaryId = null;

    async function loadPolicies() {
        const searchTerm = searchInput.value || "";
        const statusVal = statusFilter.value === 'ALL' ? "" : statusFilter.value;
        tableBody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-gray-500 font-medium">Syncing with Registry...</td></tr>`;
        errorMessageP.classList.add('hidden');

        try {
            const listPayload = {
                "_func": "list_policies",
                "search": searchTerm,
                "status": statusVal,
                "fiduciary_id_filter": localStorage.getItem("fiduciary_id")
            };

            const response = await fetch(API_URL_POLICY, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json; charset=UTF-8', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(listPayload)
            });

            if (response.status === 401) { handleLogout(); return; }

            const data = await response.json();

            if (data.status === 401) {
                alert("Session Expired: " + (data.message || "Authentication required."));
                handleLogout();
                return;
            }
            const policies = data.data || data;

            if (Array.isArray(policies)) {
                tableBody.innerHTML = '';
                if (policies.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-gray-500 italic">No policies match the criteria.</td></tr>`;
                } else {
                    policies.forEach(p => tableBody.appendChild(createPolicyRow(p)));
                }
            }
        } catch (error) {
            tableBody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-red-600 font-bold">API Connection Error.</td></tr>`;
        }
    }

    function createStatusBadge(status) {
        const colors = {
            'ACTIVE': 'bg-green-100 text-green-800',
            'UNDER_REVIEW': 'bg-blue-100 text-blue-800',
            'DRAFT': 'bg-yellow-100 text-yellow-800',
            'ARCHIVED': 'bg-gray-100 text-gray-800'
        };
        return `<span class="px-3 py-1 text-[10px] font-black rounded-full uppercase ${colors[status] || 'bg-red-50 text-red-700'}">${esc(status)}</span>`;
    }

    function createPolicyRow(policy) {
        const row = document.createElement('tr');
        row.className = "hover:bg-slate-50/50 transition-colors";
        const isDraft = policy.status === 'DRAFT';
        const isUnderReview = policy.status === 'UNDER_REVIEW';
        const isArchived = policy.status === 'ARCHIVED';

        const actionsHtml = `
            <button class="text-indigo-600 hover:text-indigo-900 font-bold text-xs mr-3" data-action="view-ropa">View ROPA</button>
            ${(isDraft && !IS_OPERATOR) ? `<button class="text-orange-600 hover:text-orange-800 font-bold text-xs mr-3" data-action="edit">Edit</button>` : ''}
            ${(isUnderReview && !IS_OPERATOR) ? `<button class="text-blue-600 hover:text-blue-800 font-bold text-xs mr-3" data-action="review-ropa">Review ROPA</button>` : ''}
            ${(!isArchived && !IS_OPERATOR) ? `<button class="text-red-600 hover:text-red-800 font-bold text-xs" data-action="delete">Delete</button>` : ''}
        `;

        row.innerHTML = `
            <td class="px-4 py-4 whitespace-nowrap text-sm font-bold text-slate-800">${esc(policy.id)}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-slate-500">${esc(policy.jurisdiction)}</td>
            <td class="px-4 py-4 whitespace-nowrap">
                ${createStatusBadge(policy.status)}
                ${isUnderReview ? '<div class="text-[10px] text-blue-500 mt-0.5">Pending DPO ROPA approval</div>' : ''}
            </td>
            <td class="px-4 py-4 whitespace-nowrap text-xs text-slate-400 font-medium">${esc(new Date(policy.effective_date).toLocaleDateString())}</td>
            <td class="px-4 py-4 whitespace-nowrap">${actionsHtml}</td>
        `;
        // Row actions bound via addEventListener instead of inline onclick (CF-02).
        const rowActions = {
            'view-ropa': () => viewRopa(policy.id),
            'edit': () => editPolicy(policy.id, policy.fiduciary_id),
            'review-ropa': () => reviewRopa(policy.id),
            'delete': () => deletePolicy(policy.id, policy.fiduciary_id)
        };
        row.querySelectorAll('button[data-action]').forEach(btn => {
            btn.addEventListener('click', rowActions[btn.getAttribute('data-action')]);
        });
        return row;
    }

    async function viewRopa(policyId) {
        currentReviewPolicyId = policyId;
        document.getElementById('modal-title').textContent = `ROPA Entries — ${policyId}`;
        document.getElementById('modal-step-hint').classList.add('hidden');
        policyForm.classList.add('hidden');
        policyModalOverlay.style.display = 'flex';
        const panel = document.getElementById('ropa-review-panel');
        panel.style.display = 'flex';
        await loadRopaReviewEntries(policyId);
    }

    async function editPolicy(id, fid) {
        showModal('Edit Policy Draft', true);
        try {
            const res = await fetch(API_URL_POLICY, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_policy", "policy_id": id, "fiduciary_id": fid })
            });
            const p = await res.json();
            editingFiduciaryId = p.fiduciary_id || fid;
            policyIdInput.value = id;
            policyIdInput.disabled = true;
            policyIdHidden.value = id;
            policyJurisdictionSelect.value = p.jurisdiction;
            const content = typeof p.policy_content === 'string' ? JSON.parse(p.policy_content) : p.policy_content;
            parsedPolicyJson = content;
            await renderPolicyPreview(content);
            document.getElementById('policy-file-name').textContent = '(loaded from existing draft)';
            document.getElementById('policy-file-name').classList.remove('hidden');

        } catch(e) { alert("Load Failed."); }
    }

    async function deletePolicy(id, fid) {
        if (!confirm(`Confirm Permanent Deletion of [${id}]?`)) return;
        try {
            const res = await fetch(API_URL_POLICY, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "delete_policy", "policy_id": id, "fiduciary_id": fid })
            });

            if (res.ok) {
                alert("Policy archived successfully.");
                loadPolicies();
            } else {
                const data = await res.json();
                alert("Action Error: " + (data.message || data.error || "Action failed."));
            }
        } catch (e) {
            console.error("Delete Error:", e);
            alert("Network Error.");
        }
    }

    function showModal(title, isEdit = false) {
        document.getElementById('modal-title').textContent = title;
        policyForm.reset();
        policyForm.classList.remove('hidden');
        document.getElementById('validation-errors').classList.add('hidden');
        document.getElementById('error-list').innerHTML = '';
        policyIdHidden.value = '';
        editingFiduciaryId = null;
        policyIdInput.disabled = false;
        document.getElementById('ropa-review-panel').style.display = 'none';
        document.getElementById('save-policy-btn').textContent = 'Next →';
        const stepHint = document.getElementById('modal-step-hint');
        stepHint.textContent = 'Step 1 of 2 — Upload policy JSON';
        stepHint.classList.remove('hidden');
        // Reset file upload state
        parsedPolicyJson = null;
        document.getElementById('policy-file-name').classList.add('hidden');
        document.getElementById('policy-preview').classList.add('hidden');
        policyModalOverlay.style.display = 'flex';
    }

    function closeModal() {
        policyModalOverlay.style.display = 'none';
        document.getElementById('ropa-review-panel').style.display = 'none';
        document.getElementById('modal-step-hint').classList.add('hidden');
        currentReviewPolicyId = null;
        loadPolicies();
    }

    function handleLogout() { localStorage.clear(); window.location.href = "../index.html"; }

    document.addEventListener('DOMContentLoaded', () => {
        tableBody = document.getElementById('policy-table-body');
        searchInput = document.getElementById('search-input');
        statusFilter = document.getElementById('status-filter');
        policyModalOverlay = document.getElementById('policy-modal-overlay');
        policyForm = document.getElementById('policy-form');
        errorMessageP = document.getElementById('policy-error-message');
        policyIdHidden = document.getElementById('policy-id-hidden');
        policyIdInput = document.getElementById('policy-id-input');
        policyJurisdictionSelect = document.getElementById('policy-jurisdiction-select');

        document.getElementById('policy-file-input').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = async function(evt) {
                try {
                    parsedPolicyJson = JSON.parse(evt.target.result);
                    await renderPolicyPreview(parsedPolicyJson);
                    document.getElementById('policy-file-name').textContent = file.name;
                    document.getElementById('policy-file-name').classList.remove('hidden');
                } catch(err) {
                    alert('Invalid JSON file: ' + err.message);
                    parsedPolicyJson = null;
                }
            };
            reader.readAsText(file);
        });

        document.getElementById('add-policy-btn').onclick = () => showModal('Create New Policy Version');
        document.getElementById('close-modal-btn').onclick = closeModal;
        document.getElementById('menu-toggle').onclick = () => { document.getElementById('sidebar').classList.toggle('open'); document.getElementById('sidebar-backdrop').classList.toggle('hidden'); };
        document.getElementById('sidebar-backdrop').onclick = () => { document.getElementById('sidebar').classList.toggle('open'); document.getElementById('sidebar-backdrop').classList.toggle('hidden'); };

        statusFilter.onchange = loadPolicies;
        searchInput.oninput = () => { clearTimeout(timeout); timeout = setTimeout(loadPolicies, 400); };

        policyForm.onsubmit = async (e) => {
            e.preventDefault();
            const isEditing = !!policyIdHidden.value;
            if (!parsedPolicyJson) { alert("Please upload a policy JSON file."); return; }
            const json = parsedPolicyJson;

            const payload = {
                "_func": isEditing ? "update_policy" : "create_policy",
                "policy_id": isEditing ? policyIdHidden.value : policyIdInput.value.trim(),
                "policy_content": json,
                "jurisdiction": policyJurisdictionSelect.value,
                "fiduciary_id": (isEditing && editingFiduciaryId) || localStorage.getItem('fiduciary_id')
            };

            const errArea = document.getElementById('validation-errors');
            const errList = document.getElementById('error-list');
            errArea.classList.add('hidden');
            errList.innerHTML = '';

            try {
                const res = await fetch(API_URL_POLICY, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok && (data.success || data.policy_id)) {
                    const savedPolicyId = data.policy_id || (isEditing ? policyIdHidden.value : policyIdInput.value.trim());
                    const fidId = payload.fiduciary_id;
                    const pubRes = await fetch(API_URL_POLICY, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                        body: JSON.stringify({ "_func": "publish_policy", "policy_id": savedPolicyId, "fiduciary_id": fidId })
                    });
                    const pubData = await pubRes.json();
                    if (pubRes.ok) {
                        statusFilter.value = 'ALL';
                        loadPolicies();
                        await showRopaReviewPanel(savedPolicyId);
                    } else {
                        alert("Publication Error: " + (pubData.message || pubData.error || "Failed to derive ROPA entries."));
                    }
                } else {
                    if (data.error && typeof data.error === 'string' && data.error.startsWith('[')) {
                        const inner = data.error.substring(1, data.error.length - 1);
                        const errs = inner.split(/,\s+(?=\$)/);
                        errs.forEach(e => {
                            const li = document.createElement('li');
                            li.textContent = e.trim();
                            errList.appendChild(li);
                        });
                        errArea.classList.remove('hidden');
                        errArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    } else {
                        alert("Error: " + (data.message || data.error || "Save failed."));
                    }
                }
            } catch (error) { alert("Network Error."); }
        };
        loadPolicies();
    });

    function handleFileDrop(e) {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (!file || !file.name.endsWith('.json')) { alert('Please drop a .json file.'); return; }
        const reader = new FileReader();
        reader.onload = async function(evt) {
            try {
                parsedPolicyJson = JSON.parse(evt.target.result);
                await renderPolicyPreview(parsedPolicyJson);
                document.getElementById('policy-file-name').textContent = file.name;
                document.getElementById('policy-file-name').classList.remove('hidden');
            } catch(err) {
                alert('Invalid JSON file: ' + err.message);
                parsedPolicyJson = null;
            }
        };
        reader.readAsText(file);
    }

    async function fetchRegisteredAppNames() {
        try {
            const res = await fetch('/api/v1/admin/app', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ _func: 'list_apps', fiduciary_id: localStorage.getItem('fiduciary_id') })
            });
            const data = await res.json();
            const apps = Array.isArray(data) ? data : (data.data || data.apps || []);
            return new Set(apps.map(a => (a.name || '').toLowerCase()));
        } catch (e) {
            return new Set();
        }
    }

    async function renderPolicyPreview(json) {
        const lang = Object.keys(json)[0];
        const block = json[lang];
        if (!block) return;

        document.getElementById('preview-title').textContent = block.title || '(no title)';

        const registeredNames = await fetchRegisteredAppNames();

        const purposes = block.data_processing_purposes || [];
        document.getElementById('preview-purposes').innerHTML =
            `<p class="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">${esc(purposes.length)} Processing Purpose(s)</p>` +
            purposes.map(p => {
                const rtpHtml = (p.recipients_or_third_parties || []).map(name => {
                    const matched = registeredNames.size === 0 || registeredNames.has(String(name).toLowerCase());
                    return matched
                        ? `<span class="text-teal-600 text-[10px] font-mono bg-teal-50 px-1.5 py-0.5 rounded">${esc(name)}</span>`
                        : `<span class="text-amber-700 text-[10px] font-mono bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded" title="No App registered with this name">⚠ ${esc(name)}</span>`;
                }).join(' ');
                return `
                <div class="flex flex-wrap gap-2 text-xs items-center py-0.5">
                    <span class="font-semibold text-slate-700">${esc(p.name || p.id)}</span>
                    <span class="text-slate-300">·</span>
                    <span class="text-slate-500 capitalize">${esc((p.legal_basis || '').replace(/_/g,' '))}</span>
                    <span class="text-slate-300">·</span>
                    <span class="text-slate-400">${esc((p.data_categories_involved || []).length)} data cat(s)</span>
                    ${rtpHtml ? `<span class="text-slate-300">·</span>${rtpHtml}` : ''}
                </div>`;
            }).join('');

        const procs = block.processors || [];
        document.getElementById('preview-processors').textContent =
            procs.length ? `Processors: ${procs.map(p => p.name).join(', ')}` : 'No processors declared';

        const subjects = block.data_subject_categories || [];
        document.getElementById('preview-subjects').textContent =
            subjects.length ? `Data subjects: ${subjects.join(', ')}` : '';

        document.getElementById('policy-preview').classList.remove('hidden');
    }

    // ---- ROPA Review Panel state ----
    let currentReviewPolicyId = null;
    let currentViewingEntryId = null;

    async function reviewRopa(policyId) {
        document.getElementById('modal-title').textContent = `ROPA Review — ${policyId}`;
        policyForm.classList.add('hidden');
        policyModalOverlay.style.display = 'flex';
        await showRopaReviewPanel(policyId);
    }

    async function showRopaReviewPanel(policyId) {
        currentReviewPolicyId = policyId;
        document.getElementById('modal-title').textContent = `ROPA Review — ${policyId}`;
        const stepHint = document.getElementById('modal-step-hint');
        stepHint.textContent = 'Step 2 of 2 — Review & publish ROPA entries';
        stepHint.classList.remove('hidden');
        policyForm.classList.add('hidden');
        const panel = document.getElementById('ropa-review-panel');
        panel.style.display = 'flex';
        await loadRopaReviewEntries(policyId);
    }

    async function loadRopaReviewEntries(policyId) {
        const tbody = document.getElementById('ropa-review-tbody');
        tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-gray-400 italic">Loading ROPA entries...</td></tr>';
        try {
            const res = await fetch('/api/v1/admin/ropa', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ _func: 'list_entries', fiduciary_id: localStorage.getItem('fiduciary_id'), status: '', limit: 100 })
            });
            const data = await res.json();
            const allEntries = Array.isArray(data) ? data : (data.data || []);
            const entries = allEntries.filter(e => parseRopaArr(e.linked_policy_ids).includes(policyId));
            if (!entries.length) {
                tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-400 italic">No ROPA entries found for this policy.</td></tr>';
                return;
            }
            tbody.innerHTML = '';
            entries.forEach(e => tbody.appendChild(buildRopaReviewRow(e)));
        } catch(err) {
            tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-red-500 font-bold">Failed to load ROPA entries.</td></tr>';
        }
    }

    function buildRopaReviewRow(e) {
        const tr = document.createElement('tr');
        tr.id = `ropa-row-${e.id}`;
        tr.className = 'hover:bg-slate-50/50 transition-colors';
        const canPublish = e.status === 'draft' || e.status === 'under_review';
        const retention = e.retention_period_days
            ? esc(`${e.retention_period_days}d (${e.retention_start_event || '—'})`)
            : '<span class="text-red-400 text-[10px] font-bold">NOT SET</span>';
        const statusColors = { draft: 'bg-yellow-100 text-yellow-800', active: 'bg-green-100 text-green-800', under_review: 'bg-blue-100 text-blue-800' };
        const badge = `<span class="px-2 py-0.5 text-[10px] font-black rounded-full uppercase ${statusColors[e.status] || 'bg-gray-100 text-gray-600'}">${esc(e.status)}</span>`;
        const actions = `
            <button class="text-teal-700 hover:text-teal-900 font-bold text-xs mr-2" data-action="view">View</button>
            ${canPublish ? `<button class="text-green-600 hover:text-green-800 font-bold text-xs" data-action="publish">Publish</button>` : '<span class="text-green-600 font-bold text-xs">Active</span>'}
        `;
        tr.innerHTML = `
            <td class="px-4 py-3 text-sm font-bold text-slate-800 max-w-[240px]">
                <div class="truncate" title="${esc(e.activity_name)}">${esc(e.activity_name)}</div>
                <div class="text-[10px] font-mono text-slate-400 mt-0.5">${esc(e.id.slice(0,8))}…</div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-500 whitespace-nowrap capitalize">${esc((e.legal_basis||'').replace(/_/g,' '))}</td>
            <td class="px-4 py-3 whitespace-nowrap">${badge}</td>
            <td class="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">${retention}</td>
            <td class="px-4 py-3 whitespace-nowrap">${actions}</td>
        `;
        // Bound via addEventListener (CF-02): the activity name never passes through an inline JS string.
        tr.querySelector('button[data-action="view"]').addEventListener('click', () => viewRopaEntryInline(e.id));
        const publishBtn = tr.querySelector('button[data-action="publish"]');
        if (publishBtn) publishBtn.addEventListener('click', () => publishRopaEntry(e.id, e.activity_name));
        return tr;
    }

    async function viewRopaEntryInline(id) {
        currentViewingEntryId = id;
        const modal = document.getElementById('ropa-entry-modal');
        modal.style.display = 'flex';
        document.getElementById('rem-checklist').innerHTML = '<p class="text-xs text-slate-400 italic">Loading...</p>';
        try {
            const [entryRes, validateRes] = await Promise.all([
                fetch('/api/v1/admin/ropa', { method:'POST', headers:{ 'Content-Type':'application/json','Authorization':`Bearer ${AUTH_TOKEN}` }, body: JSON.stringify({ _func:'get_entry', id }) }),
                fetch('/api/v1/admin/ropa', { method:'POST', headers:{ 'Content-Type':'application/json','Authorization':`Bearer ${AUTH_TOKEN}` }, body: JSON.stringify({ _func:'validate_completeness', id }) })
            ]);
            const e = await entryRes.json();
            const v = await validateRes.json();
            document.getElementById('rem-title').textContent = e.activity_name || 'Entry';
            document.getElementById('rem-subtitle').textContent = `ID: ${e.id} • Status: ${e.status} • v${e.version}`;
            document.getElementById('rem-legal-basis').textContent = (e.legal_basis || '—').replace(/_/g,' ');
            document.getElementById('rem-purpose').textContent = e.purpose || '—';
            document.getElementById('rem-retention').textContent = e.retention_period_days ? `${e.retention_period_days} days (${e.retention_start_event || '—'})` : '—';
            document.getElementById('rem-security').textContent = e.security_measures || '—';
            document.getElementById('rem-data-categories').textContent = prettyRopaJson(e.data_categories);
            document.getElementById('rem-data-subjects').textContent = prettyRopaJson(e.data_subject_categories);
            document.getElementById('rem-processors').textContent = prettyRopaJson(e.processors);
            document.getElementById('rem-cross-border').textContent = prettyRopaJson(e.cross_border_transfers);
            const pubBtn = document.getElementById('rem-publish-btn');
            pubBtn.dataset.name = e.activity_name;
            const canPublish = e.status === 'draft' || e.status === 'under_review';
            canPublish ? pubBtn.classList.remove('hidden') : pubBtn.classList.add('hidden');
            renderRopaChecklist(v);
        } catch(err) {
            document.getElementById('rem-checklist').innerHTML = '<p class="text-xs text-red-500">Failed to load.</p>';
        }
    }

    function renderRopaChecklist(v) {
        const checkEl = document.getElementById('rem-checklist');
        const banner  = document.getElementById('rem-completeness-banner');
        const allFields = [
            'activity_name','purpose','legal_basis','data_categories','data_subject_categories',
            'retention_period_days','retention_start_event','security_measures','cross_border_transfers'
        ];
        const missingArr = Array.isArray(v.missing_fields) ? v.missing_fields.map(f => f.split(' ')[0]) : [];
        const missing = new Set(missingArr);
        checkEl.innerHTML = allFields.map(f => {
            const ok = !Array.from(missing).some(m => m.startsWith(f));
            const label = f.replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase());
            return `<div style="display:flex;align-items:center;gap:8px;font-size:0.8rem;padding:4px 0;color:${ok?'#16a34a':'#dc2626'}">
                <span>${ok ? '✓' : '✗'}</span><span>${esc(label)}</span>
            </div>`;
        }).join('');
        const nonDpoMissing = missingArr.filter(f => !f.startsWith('dpo_id'));
        if (v.complete || nonDpoMissing.length === 0) {
            banner.textContent = '✓ Ready to publish — your DPO accountability will be recorded automatically';
            banner.className = 'mt-4 p-2 rounded-lg text-center text-xs font-bold bg-green-100 text-green-700';
        } else {
            banner.textContent = `${nonDpoMissing.length} field(s) incomplete`;
            banner.className = 'mt-4 p-2 rounded-lg text-center text-xs font-bold bg-amber-100 text-amber-700';
        }
        banner.classList.remove('hidden');
    }

    function closeRopaEntryModal() {
        document.getElementById('ropa-entry-modal').style.display = 'none';
        currentViewingEntryId = null;
    }

    async function publishRopaEntryFromModal() {
        const id = currentViewingEntryId;
        const name = document.getElementById('rem-publish-btn').dataset.name || 'this entry';
        if (!confirm(`Publish "${name}"?\n\nThis will transition the entry to ACTIVE status. All required fields must be complete.`)) return;
        await doPublishRopaEntry(id);
        closeRopaEntryModal();
    }

    async function publishRopaEntry(id, name) {
        if (!confirm(`Publish "${name}"?\n\nThis will transition the entry to ACTIVE status. All required fields must be complete.`)) return;
        await doPublishRopaEntry(id);
    }

    async function doPublishRopaEntry(id) {
        const res = await fetch('/api/v1/admin/ropa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
            body: JSON.stringify({ _func: 'publish_entry', id })
        });
        const data = await res.json();
        if (res.ok && data.success) {
            if (currentReviewPolicyId) await loadRopaReviewEntries(currentReviewPolicyId);
        } else {
            const msg = data.missing_fields
                ? `Cannot publish. Missing fields:\n• ${data.missing_fields.join('\n• ')}`
                : (data.message || 'Publish failed.');
            alert(msg);
        }
    }

    function parseRopaArr(val) {
        if (!val) return [];
        if (Array.isArray(val)) return val;
        try { return JSON.parse(val); } catch(e) { return []; }
    }

    function prettyRopaJson(val) {
        if (val == null) return '—';
        if (typeof val === 'string') {
            try { return JSON.stringify(JSON.parse(val), null, 0); } catch(e) { return val; }
        }
        return JSON.stringify(val);
    }

    window.editPolicy = editPolicy;
    window.deletePolicy = deletePolicy;
    window.closeModal = closeModal;
    window.reviewRopa = reviewRopa;
    window.viewRopaEntryInline = viewRopaEntryInline;
    window.publishRopaEntry = publishRopaEntry;
    window.publishRopaEntryFromModal = publishRopaEntryFromModal;
    window.closeRopaEntryModal = closeRopaEntryModal;
