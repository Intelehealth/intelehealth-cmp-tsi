// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's controls carry data-action and are wired here. One delegated listener serves
// both the static controls and those rendered later (reveal, revoke), and resolves the
// target function at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        print: () => window.print(),
        revealPrincipal: (el) => revealPrincipal(el),
        viewRecentPrincipal: (el) => viewRecentPrincipal(el),
        revealConsentRecord: (el) => revealConsentRecord(el),
        revealGuardian: (el) => revealGuardian(el),
        revokePurpose: (el) => revokePurpose(el),
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

    // An element whose text (never markup) is `text`.
    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text != null) node.textContent = String(text);
        return node;
    }

    // --- Configuration ---
    const API_URL_CONSENT = '/api/v1/consent';
    const API_URL_APP = '/api/v1/admin/app';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    if (localStorage.getItem('role') === 'OPERATOR') {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
    }
    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'DPO User';

    async function postJson(url, payload) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
            body: JSON.stringify(payload)
        });
        let body = {};
        try { body = await response.json(); } catch (e) { body = {}; }
        return { response, body };
    }

    // --- Logged reveal (reveal_user_id) ---
    // Console reads carry masked principal identifiers and no IP. A DPO or administrator
    // sees a value in the clear only through reveal_user_id, which writes an audit row
    // before answering and allows 20 reveals a minute. A revealed value lives only in the
    // page (re-masked after REMASK_MS) and is never written to localStorage.
    const API_URL_PII = '/api/v1/admin/pii';
    const REVEAL_LABEL = 'Reveal — this action is logged';
    const REMASK_MS = 30000;
    const CAN_REVEAL = ['DPO', 'ADMIN'].includes(String(localStorage.getItem('role') || '').toUpperCase());
    let revealConfirmed = false;

    function revealButton(action, data) {
        if (!CAN_REVEAL) return null;
        const btn = el('button', 'reveal-btn ml-1 text-xs text-amber-700 hover:text-amber-900 underline', REVEAL_LABEL);
        btn.type = 'button';
        btn.setAttribute('data-action', action);
        Object.entries(data || {}).forEach(([k, v]) => btn.setAttribute(`data-${k}`, v));
        return btn;
    }

    // The revealed fields, or null (declined, refused or failed: the reason is shown).
    async function revealFields(source, key) {
        if (!CAN_REVEAL) return null;
        if (!revealConfirmed) {
            if (!confirm("This reveal will be recorded in the audit log against your account. Continue?")) return null;
            revealConfirmed = true;
        }
        const payload = { "_func": "reveal_user_id", "source": source, "fiduciary_id": FIDUCIARY_ID };
        if (source === 'data_principal') payload.user_ref = key; else payload.id = key;
        let result;
        try {
            result = await postJson(API_URL_PII, payload);
        } catch (e) {
            alert("Reveal failed: the server could not be reached.");
            return null;
        }
        const { response, body } = result;
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

    // Puts each revealed value in place of its masked text, then masks it again (unless
    // the element has since been re-rendered with other content).
    function showRevealed(pairs, buttons) {
        const originals = pairs.map(([node]) => node.textContent);
        const shown = pairs.map(([node, value]) => {
            node.textContent = value == null || value === '' ? 'N/A' : String(value);
            return node.textContent;
        });
        buttons.forEach(b => { b.disabled = true; });
        setTimeout(() => {
            pairs.forEach(([node], i) => { if (node.textContent === shown[i]) node.textContent = originals[i]; });
            buttons.forEach(b => { b.disabled = false; });
        }, REMASK_MS);
    }

    async function withButton(btn, fn) {
        btn.disabled = true;
        const shown = await fn();
        if (!shown) btn.disabled = false;
    }

    // --- Global DOM Element Variables ---
    let sidebar, menuToggle, backdrop;
    let principalSearchForm, principalIdInput, searchMessage;
    let consentHistoryCard, principalDisplayId, consentTableBody, consentDetailModalOverlay, closeDetailModalBtn;
    let modalRecordId, modalRecordStatus, granularConsentDetails, provenanceDetails;
    let principalStatusCard, overallStatusBadge, mainInitiateErasureBtn;
    let recentPrincipalsCard, recentPrincipalsBody;
    let guardianSection, guardianDetails, auditTrailDetails, modalRevealBtn;

    // The principal this page has loaded, in the clear: typed by the DPO, or obtained
    // through a logged reveal. Held in memory only; erasure and revoke need it.
    let currentUserId = null;
    // Whether the DPO typed it (and may therefore see it on screen) or it came from a reveal.
    let currentUserTyped = false;
    // The record the detail modal shows.
    let currentRecordId = null;

    // --- Helper Functions ---

    function toggleMenu() {
        sidebar.classList.toggle('open');
        backdrop.classList.toggle('hidden');
    }

    function showModal() {
        consentDetailModalOverlay.style.display = 'flex';
    }

    function closeModal() {
        consentDetailModalOverlay.style.display = 'none';
    }

    function formatDateTime(value) {
        return value ? new Date(value).toLocaleString() : 'N/A';
    }

    function createStatusBadge(status, isActive) {
        let colorClass = 'bg-gray-100 text-gray-800';
        const s = (status || '').toUpperCase();

        if (isActive === true) {
            colorClass = 'bg-green-100 text-green-700 border border-green-200';
            if (s === 'DENIED_ALL' || s === 'WITHDRAWN' || s === 'ERASURE_REQUEST' || s === 'CONSENT_WITHDRAWN') {
                colorClass = 'bg-red-100 text-red-700 border border-red-200';
            }
        } else if (isActive === false) {
             colorClass = 'bg-gray-200 text-gray-600'; // Archived/Inactive
        }
        return `<span class="px-3 py-1 text-xs font-bold rounded-full uppercase ${colorClass}">${esc(s.replace(/_/g, ' '))}</span>`;
    }

    function createHistoryRow(record) {
        const row = document.createElement('tr');
        const isActive = record.is_active_consent;

        row.innerHTML = `
            <td class="px-4 py-3 text-sm font-mono text-gray-700">...${esc(record.id.slice(-8))}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(record.policy_id)} (v${esc(record.policy_version)})</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(new Date(record.timestamp).toLocaleString())}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(record.consent_mechanism)}</td>
            <td class="px-4 py-3 text-sm">${createStatusBadge(record.consent_status_general, isActive)}</td>
            <td class="px-4 py-3 text-sm font-bold text-slate-500">${isActive ? 'Yes' : 'No'}</td>
            <td class="px-4 py-3 text-sm">
                <button data-rid="${esc(record.id)}" class="view-record-btn text-indigo-600 hover:text-indigo-900 font-bold text-sm">View Details</button>
            </td>
        `;
        const btn = row.querySelector('.view-record-btn');
        btn.addEventListener('click', () => viewConsentRecord(btn.dataset.rid));
        return row;
    }

    // --- Core Logic ---

    // list_principals returns the identifier masked, with user_ref (its lookup HMAC) as the
    // handle reveal_user_id takes for source data_principal.
    function createRecentPrincipalRow(principal) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="px-4 py-3 text-sm font-mono text-gray-700"><span class="principal-id"></span></td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(principal.last_consent_mechanism || 'N/A')}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(principal.age_category || 'N/A')}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(principal.verification_status || 'N/A')}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(new Date(principal.created_at).toLocaleDateString())}</td>
            <td class="px-4 py-3 text-sm">
                <button type="button" data-action="viewRecentPrincipal" class="text-indigo-600 hover:text-indigo-900 font-bold text-sm">View</button>
            </td>
        `;
        const idCell = row.querySelector('.principal-id');
        idCell.textContent = principal.user_id || 'N/A';
        row.querySelector('[data-action="viewRecentPrincipal"]').setAttribute('data-ref', principal.user_ref || '');
        const reveal = principal.user_ref ? revealButton('revealPrincipal', { ref: principal.user_ref }) : null;
        if (reveal) idCell.after(reveal);
        return row;
    }

    function revealPrincipal(btn) {
        return withButton(btn, async () => {
            const fields = await revealFields('data_principal', btn.getAttribute('data-ref'));
            if (!fields) return false;
            showRevealed([[btn.previousElementSibling, fields.user_id]], [btn]);
            return true;
        });
    }

    // The history lookup needs the identifier in the clear; for a masked row that is a
    // logged reveal, so only a DPO or administrator can drill down from this list.
    async function viewRecentPrincipal(btn) {
        const ref = btn.getAttribute('data-ref');
        if (!CAN_REVEAL || !ref) {
            alert("This identifier is masked. Enter the full Data Principal ID in the search box to load its history.");
            return;
        }
        btn.disabled = true;
        const fields = await revealFields('data_principal', ref);
        btn.disabled = false;
        if (!fields || !fields.user_id) return;
        principalIdInput.value = '';
        loadConsentHistory(fields.user_id, false);
    }

    async function loadRecentPrincipals() {
        try {
            const { body: principals } = await postJson(API_URL_CONSENT, { "_func": "list_principals", "fiduciary_id": FIDUCIARY_ID, "limit": 20 });

            recentPrincipalsBody.innerHTML = '';
            if (Array.isArray(principals) && principals.length > 0) {
                principals.forEach(p => recentPrincipalsBody.appendChild(createRecentPrincipalRow(p)));
            } else {
                recentPrincipalsBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">No principals onboarded yet.</td></tr>`;
            }
        } catch (error) {
            recentPrincipalsBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-red-600">Error loading recent principals.</td></tr>`;
        }
    }

    async function loadConsentHistory(principalIdentifier, typed) {
        recentPrincipalsCard.classList.add('hidden');
        consentHistoryCard.classList.add('hidden');
        principalStatusCard.classList.add('hidden');
        consentTableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">Searching...</td></tr>`;
        searchMessage.classList.add('hidden');
        currentUserId = principalIdentifier;
        currentUserTyped = typed;

        try {
            const payload = {
                "_func": "list_consent_history",
                "user_id": principalIdentifier,
                "fiduciary_id": FIDUCIARY_ID
            };

            const { body: responseData } = await postJson(API_URL_CONSENT, payload);

            if (responseData.status === 401) {
                alert("Session Expired: " + (responseData.message || "Authentication required."));
                handleLogout();
                return;
            }
            const records = responseData.data || responseData;

            if (Array.isArray(records) && records.length > 0) {
                consentTableBody.innerHTML = '';
                const latest = records[0];
                overallStatusBadge.innerHTML = createStatusBadge(latest.consent_status_general, latest.is_active_consent);

                if (latest.consent_mechanism !== 'ERASURE_REQUEST' && latest.consent_status_general !== 'ERASURE_REQUESTED') {
                    mainInitiateErasureBtn.classList.remove('hidden');
                    mainInitiateErasureBtn.onclick = () => initiateErasurePurge();
                } else {
                    mainInitiateErasureBtn.classList.add('hidden');
                }

                principalStatusCard.classList.remove('hidden');
                records.forEach(record => {
                    consentTableBody.appendChild(createHistoryRow(record));
                });
                // The DPO's own input is shown as typed; a revealed identifier stays masked here.
                principalDisplayId.textContent = typed ? principalIdentifier : (latest.user_id || '');
                consentHistoryCard.classList.remove('hidden');
            } else {
                consentTableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">No records found.</td></tr>`;
                searchMessage.classList.remove('hidden');
                recentPrincipalsCard.classList.remove('hidden');
            }
        } catch (error) {
            consentTableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-red-600">Error loading data.</td></tr>`;
        }
    }

    // A consent decision's purpose id, by the keys the server reads (data_point_id first).
    function pointPurposeId(point) {
        for (const key of ['data_point_id', 'purpose_id', 'id']) {
            if (point[key] != null && point[key] !== '') return String(point[key]);
        }
        return '';
    }

    function grantBadge(anyGranted, anyDenied) {
        if (anyGranted && anyDenied) return el('span', 'text-amber-600 font-bold', 'PARTIALLY GRANTED');
        if (anyGranted) return el('span', 'text-green-600 font-bold', 'GRANTED');
        return el('span', 'text-red-600 font-bold', 'DENIED');
    }

    function renderGranularConsents(record) {
        granularConsentDetails.replaceChildren();
        const byPurpose = new Map();
        (record.data_point_consents || []).forEach(point => {
            if (!point || typeof point !== 'object') return;
            const pid = pointPurposeId(point);
            if (!pid) return;
            if (!byPurpose.has(pid)) {
                byPurpose.set(pid, { label: point.purpose_agreed_to || point.name || pid, anyGranted: false, anyDenied: false });
            }
            const group = byPurpose.get(pid);
            if (point.consent_granted === true) group.anyGranted = true; else group.anyDenied = true;
        });
        if (byPurpose.size === 0) {
            granularConsentDetails.appendChild(el('p', 'text-gray-500', 'No granular purposes recorded.'));
            return;
        }
        byPurpose.forEach((group, pid) => {
            const item = el('div', 'policy-detail-item');
            item.appendChild(el('p', 'text-gray-800 font-medium', `${group.label}:`));
            const line = el('p', 'ml-4');
            line.appendChild(grantBadge(group.anyGranted, group.anyDenied));
            // Revoke one purpose of the live record; every other purpose stays as granted.
            if (record.is_active_consent && group.anyGranted) {
                const revoke = el('button', 'ml-3 text-xs text-red-600 hover:text-red-800 font-semibold underline', 'Revoke this purpose');
                revoke.type = 'button';
                revoke.setAttribute('data-action', 'revokePurpose');
                revoke.setAttribute('data-purpose-id', pid);
                revoke.setAttribute('data-purpose-label', group.label);
                revoke.setAttribute('data-policy-id', record.policy_id || '');
                line.appendChild(revoke);
            }
            item.appendChild(line);
            granularConsentDetails.appendChild(item);
        });
    }

    function renderProvenance(record) {
        provenanceDetails.replaceChildren();
        const line = (label, value) => {
            const p = el('p');
            p.appendChild(el('strong', null, `${label}: `));
            p.appendChild(value instanceof Node ? value : document.createTextNode(value));
            provenanceDetails.appendChild(p);
            return p;
        };
        line('Policy Ref', `${record.policy_id} (v${record.policy_version || '—'})`);
        if (record.ropa_entry_id) line('ROPA Entry', record.ropa_activity_name || record.ropa_entry_id);
        line('Time', `${formatDateTime(record.timestamp)} (${record.consent_mechanism || 'N/A'})`);
        // Console reads carry no IP (ip_address is null); a reveal of the record shows it.
        const ipSpan = el('span', null, record.ip_address || 'N/A');
        ipSpan.id = 'modal-ip-address';
        const ipLine = line('IP', ipSpan);
        const ipReveal = revealButton('revealConsentRecord');
        if (ipReveal) ipLine.appendChild(ipReveal);
        line('User Agent', record.user_agent || 'N/A');
    }

    async function viewConsentRecord(recordId) {
        currentRecordId = recordId;
        showModal();
        granularConsentDetails.replaceChildren(el('p', 'text-gray-500', `Fetching record ${recordId}...`));
        provenanceDetails.replaceChildren();
        guardianSection.classList.add('hidden');
        guardianDetails.replaceChildren();
        modalRecordId.textContent = '';
        modalRecordStatus.innerHTML = '';
        if (modalRevealBtn) modalRevealBtn.disabled = false;

        try {
            const { response, body: record } = await postJson(API_URL_CONSENT, {
                "_func": "get_consent_record_details",
                "record_id": recordId,
                "fiduciary_id": FIDUCIARY_ID
            });

            if (response.ok && record) {
                modalRecordId.textContent = currentUserTyped ? currentUserId : (record.user_id || 'N/A');
                modalRecordStatus.innerHTML = createStatusBadge(record.consent_status_general, record.is_active_consent);
                renderProvenance(record);
                renderGranularConsents(record);
                // Only a minor's record rests on a guardian verification.
                if (record.verification_log_id) {
                    guardianSection.classList.remove('hidden');
                    loadGuardianVerification(recordId);
                }
            } else {
                granularConsentDetails.replaceChildren(el('p', 'text-red-600', record.message || 'Error fetching details.'));
            }
        } catch (error) {
            granularConsentDetails.replaceChildren(el('p', 'text-red-600', 'Error fetching details.'));
        }

        loadConsentAuditTrail(recordId);
    }

    // One reveal of a consent record returns its principal and its IP together.
    function revealConsentRecord(btn) {
        const recordId = currentRecordId;
        return withButton(btn, async () => {
            const fields = await revealFields('consent_record', recordId);
            if (!fields || recordId !== currentRecordId) return false;
            const pairs = [[modalRecordId, fields.user_id]];
            const ipSpan = document.getElementById('modal-ip-address');
            if (ipSpan) pairs.push([ipSpan, fields.ip_address]);
            showRevealed(pairs, Array.from(document.querySelectorAll('[data-action="revealConsentRecord"]')));
            return true;
        });
    }

    async function loadGuardianVerification(recordId) {
        guardianDetails.replaceChildren(el('p', 'text-gray-500', 'Loading...'));
        try {
            const { response, body: v } = await postJson(API_URL_CONSENT, {
                "_func": "get_parental_verification",
                "consent_record_id": recordId,
                "fiduciary_id": FIDUCIARY_ID
            });
            if (recordId !== currentRecordId) return;
            guardianDetails.replaceChildren();
            if (response.status === 404) {
                guardianDetails.appendChild(el('p', 'text-gray-500', 'No guardian verification on record for this consent.'));
                return;
            }
            if (!response.ok) {
                guardianDetails.appendChild(el('p', 'text-red-600', v.message || 'Error fetching guardian verification.'));
                return;
            }
            const line = (label, valueNode) => {
                const p = el('p');
                p.appendChild(el('strong', null, `${label}: `));
                p.appendChild(valueNode);
                guardianDetails.appendChild(p);
                return p;
            };
            const guardian = el('span', 'font-mono', v.guardian_id || 'N/A');
            guardian.id = 'guardian-id-display';
            const guardianLine = line('Guardian', guardian);
            line('Verified Via', document.createTextNode(`${v.verification_mechanism || 'N/A'} (${v.provider_name || 'N/A'})`));
            line('Status', document.createTextNode(v.verification_status || 'N/A'));
            line('Verified At', document.createTextNode(formatDateTime(v.verified_at)));
            if (v.verification_detail) line('Detail', document.createTextNode(v.verification_detail));
            const ref = el('span', 'font-mono', v.verification_ref_id || 'N/A');
            ref.id = 'guardian-ref-display';
            const refLine = line('Evidence Reference', ref);
            const proof = el('span', null, v.has_proof_metadata ? 'On file' : 'None');
            proof.id = 'guardian-proof-display';
            line('Proof', proof);
            // One reveal returns the guardian id, the evidence reference and the proof together.
            [guardianLine, refLine].forEach(p => {
                const btn = revealButton('revealGuardian', { id: v.verification_log_id });
                if (btn) p.appendChild(btn);
            });
        } catch (e) {
            guardianDetails.replaceChildren(el('p', 'text-red-600', 'Error fetching guardian verification.'));
        }
    }

    function revealGuardian(btn) {
        return withButton(btn, async () => {
            const fields = await revealFields('parental_verification', btn.getAttribute('data-id'));
            if (!fields) return false;
            const proof = fields.proof_metadata;
            const pairs = [
                [document.getElementById('guardian-id-display'), fields.guardian_id],
                [document.getElementById('guardian-ref-display'), fields.verification_ref_id],
                [document.getElementById('guardian-proof-display'),
                    proof == null ? null : (typeof proof === 'string' ? proof : JSON.stringify(proof))],
            ].filter(([node]) => node);
            showRevealed(pairs, Array.from(document.querySelectorAll('[data-action="revealGuardian"]')));
            return true;
        });
    }

    // "Submitted via" for a ledger event. An APP event names its app by service_id when one
    // was logged (looked up once per app); many log none, and read by their service_type.
    const SERVICE_LABELS = {
        APP: 'App',
        API: 'API',
        CONSOLE: 'Console',
        DPO_CONSOLE: 'DPO Console',
        ADMIN_CONSOLE: 'Admin Console',
        SYSTEM: 'System',
        PRINCIPAL: 'Principal (self-service)',
        PROCESSOR: 'Processor',
    };
    const appLabelCache = {};

    async function resolveServiceLabel(serviceType, serviceId) {
        const base = SERVICE_LABELS[serviceType] || (serviceType ? String(serviceType).replace(/_/g, ' ') : 'Unknown');
        if (serviceType !== 'APP' || !serviceId) return base;
        if (!appLabelCache[serviceId]) {
            appLabelCache[serviceId] = postJson(API_URL_APP, { "_func": "get_app", "app_id": serviceId, "fiduciary_id": FIDUCIARY_ID })
                .then(({ response, body }) => (response.ok && body.name ? `${body.name} (App)` : `App (${serviceId})`))
                .catch(() => `App (${serviceId})`);
        }
        return appLabelCache[serviceId];
    }

    // Every ledger event about this consent record, grouped by purpose: what the
    // tamper-evident audit log recorded, independent of the live consent row.
    async function loadConsentAuditTrail(recordId) {
        auditTrailDetails.replaceChildren(el('p', 'text-gray-500', 'Loading...'));
        try {
            const { response, body } = await postJson(API_URL_CONSENT, {
                "_func": "get_consent_audit_trail",
                "consent_record_id": recordId,
                "fiduciary_id": FIDUCIARY_ID
            });
            if (recordId !== currentRecordId) return;
            if (response.status === 403) {
                auditTrailDetails.replaceChildren(el('p', 'text-gray-500', 'Your role cannot read the audit ledger.'));
                return;
            }
            if (!response.ok) {
                auditTrailDetails.replaceChildren(el('p', 'text-red-600', body.message || 'Error fetching audit trail.'));
                return;
            }
            const purposes = body.purposes || [];
            const labels = await Promise.all(purposes.flatMap(p => (p.events || []).map(e => resolveServiceLabel(e.service_type, e.service_id))));
            if (recordId !== currentRecordId) return;
            auditTrailDetails.replaceChildren();
            if (purposes.length === 0) {
                auditTrailDetails.appendChild(el('p', 'text-gray-500', 'No audit log entries found for this consent.'));
                return;
            }
            let i = 0;
            purposes.forEach(group => {
                const section = el('div', 'policy-detail-item');
                const heading = group.purpose_id && group.purpose_id !== group.purpose_name
                    ? `${group.purpose_name} (${group.purpose_id})` : group.purpose_name;
                section.appendChild(el('p', 'text-gray-800 font-semibold', heading));
                const fields = group.fields || [];
                section.appendChild(el('p', 'ml-4 text-gray-500', `Fields: ${fields.length ? fields.join(', ') : 'None listed'}`));
                const list = el('ul', 'ml-4 mt-1 space-y-1');
                (group.events || []).forEach(event => {
                    const li = el('li');
                    li.appendChild(el('span', 'font-medium', `${formatDateTime(event.timestamp)} — ${String(event.audit_action || '').replace(/_/g, ' ')}`));
                    li.appendChild(el('span', 'text-gray-600', ` · Submitted via: ${labels[i++]}`));
                    if (event.current_log_hash) {
                        const hash = el('code', 'block text-[10px] text-gray-500 break-all', `Hash: ${event.current_log_hash}`);
                        li.appendChild(hash);
                    }
                    list.appendChild(li);
                });
                section.appendChild(list);
                auditTrailDetails.appendChild(section);
            });
        } catch (e) {
            auditTrailDetails.replaceChildren(el('p', 'text-red-600', 'Error fetching audit trail.'));
        }
    }

    // Withdraws one purpose (e.g. resolving a grievance about one use of the data) from
    // this record's policy; every other granted purpose is unaffected.
    async function revokePurpose(btn) {
        const purposeId = btn.getAttribute('data-purpose-id');
        const label = btn.getAttribute('data-purpose-label') || purposeId;
        const policyId = btn.getAttribute('data-policy-id');
        if (!currentUserId) { alert("No principal identifier available."); return; }
        if (!confirm(`Confirm: Revoke consent for purpose "${label}" only? Every other granted purpose on this record is unaffected.`)) return;

        btn.disabled = true;
        try {
            const payload = {
                "_func": "withdraw_consent",
                "user_id": currentUserId,
                "purpose_ids": [purposeId],
                "reason": "DPO revoked a single purpose.",
                "fiduciary_id": FIDUCIARY_ID
            };
            if (policyId) payload.policy_id = policyId;
            const { response, body } = await postJson(API_URL_CONSENT, payload);
            if (response.ok) {
                alert(`Purpose "${label}" revoked.`);
                closeModal();
                loadConsentHistory(currentUserId, currentUserTyped);
            } else {
                alert("Failed to revoke purpose: " + (body.message || `status ${response.status}`));
                btn.disabled = false;
            }
        } catch (e) {
            alert("Error revoking purpose.");
            btn.disabled = false;
        }
    }

    async function initiateErasurePurge() {
        const userId = currentUserId;
        if (!userId) { alert("No principal identifier available."); return; }
        const shown = currentUserTyped ? userId : principalDisplayId.textContent;
        if (confirm(`Confirm: Initiate full Data Erasure/Purge workflow for Data Principal ID ${shown}?`)) {
            try {
                const { response } = await postJson(API_URL_CONSENT, {
                    "_func": "erasure_request",
                    "user_id": userId,
                    "language_selected": "en",
                    "reason": "DPO initiated erasure.",
                    "fiduciary_id": FIDUCIARY_ID
                });
                if (response.ok) {
                    alert("Erasure request submitted.");
                    loadConsentHistory(userId, currentUserTyped);
                }
            } catch (e) { alert("Error initiating erasure."); }
        }
    }

    function handleLogout() {
        localStorage.clear();
        window.location.href = "../index.html";
    }

    document.addEventListener('DOMContentLoaded', async () => {
        sidebar = document.getElementById('sidebar');
        menuToggle = document.getElementById('menu-toggle');
        backdrop = document.getElementById('sidebar-backdrop');
        principalSearchForm = document.getElementById('principal-search-form');
        principalIdInput = document.getElementById('principal-id-input');
        searchMessage = document.getElementById('search-message');
        consentHistoryCard = document.getElementById('consent-history-card');
        principalDisplayId = document.getElementById('principal-display-id');
        consentTableBody = document.getElementById('consent-table-body');
        consentDetailModalOverlay = document.getElementById('consent-detail-modal-overlay');
        closeDetailModalBtn = document.getElementById('close-detail-modal-btn');
        modalRecordId = document.getElementById('modal-record-id');
        modalRecordStatus = document.getElementById('modal-record-status');
        granularConsentDetails = document.getElementById('granular-consent-details');
        provenanceDetails = document.getElementById('provenance-details');
        principalStatusCard = document.getElementById('principal-status-card');
        overallStatusBadge = document.getElementById('overall-status-badge');
        mainInitiateErasureBtn = document.getElementById('main-initiate-erasure-btn');
        recentPrincipalsCard = document.getElementById('recent-principals-card');
        recentPrincipalsBody = document.getElementById('recent-principals-body');
        guardianSection = document.getElementById('guardian-verification-section');
        guardianDetails = document.getElementById('guardian-verification-details');
        auditTrailDetails = document.getElementById('audit-trail-details');
        modalRevealBtn = document.getElementById('modal-reveal-btn');

        if (CAN_REVEAL) {
            modalRevealBtn.classList.remove('hidden');
        } else {
            modalRevealBtn.remove();
            modalRevealBtn = null;
        }

        menuToggle.addEventListener('click', toggleMenu);
        backdrop.addEventListener('click', toggleMenu);
        closeDetailModalBtn.addEventListener('click', closeModal);

        principalSearchForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const identifier = principalIdInput.value.trim();
            if (identifier) loadConsentHistory(identifier, true);
        });

        loadRecentPrincipals();
    });

    window.viewConsentRecord = viewConsentRecord;
    window.toggleMenu = toggleMenu;
