// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        triggerFileInput: () => triggerFileInput(),
        switchView: (el) => switchView(el.getAttribute('data-arg')),
        simulateScan: () => simulateScan(),
        showLawInfo: () => alert('DPDP Act: This wallet demonstrates Section 6 (Withdrawal) and Section 12 (Erasure) via secure sync tokens.'),
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
    const changeHandlers = {
        handleFileSelect: (el, e) => handleFileSelect(e),
    };
    document.querySelectorAll('[data-change-action]').forEach((el) => {
        const fn = changeHandlers[el.getAttribute('data-change-action')];
        if (fn) el.addEventListener('change', (e) => fn(el, e));
    });
})();

    // P11-10: a stored consent decision is read exactly as the server reads it
    // (services/base.py point_purpose_id, services/consent.py _point_granted).
    function pointPurposeId(point) {
        if (!point || typeof point !== 'object') return '';
        for (const key of ['data_point_id', 'purpose_id', 'id']) {
            if (point[key] != null && point[key] !== '') {
                const text = String(point[key]).trim();
                return text === 'ALL' ? text : text.toLowerCase();
            }
        }
        return '';
    }
    function pointGranted(point) {
        if (!point || typeof point !== 'object') return false;
        let granted = point.consent_granted;
        if (granted == null) {
            granted = ['granted', 'true', 'consent_given'].includes(String(point.status == null ? '' : point.status).toLowerCase());
        } else if (Array.isArray(granted)) {
            granted = granted.length > 0;
        } else if (typeof granted === 'object') {
            granted = Object.keys(granted).length > 0;
        }
        if (!granted) return false;
        if (point.consent_expiry) {
            const expiry = Date.parse(String(point.consent_expiry));
            if (!Number.isNaN(expiry) && expiry <= Date.now()) return false;
        }
        return true;
    }
    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    function personaLabel(s) {
        if (!s) return '';
        return String(s).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }

    // --- State & Config ---
    let state = {
        fiduciaries: [],
        activeFidId: null
    };

    const API_BASE_URL = (typeof config !== 'undefined' && config.tsi_dpdp_cms_apibaseurl)
        ? config.tsi_dpdp_cms_apibaseurl
        : window.location.origin;
    const WALLET_API = `${API_BASE_URL}/api/v1/client/wallet`;

    // --- Integration Helper ---

    async function syncWithBackend(fidId, userId, syncToken, syncUrl, payload) {
        showLoading(true);
        try {
            const response = await fetch(syncUrl || WALLET_API, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...payload,
                    sync_token: syncToken,
                    fiduciary_id: fidId,
                    user_id: userId // DYNAMIC identity
                })
            });

            if (!response.ok) throw new Error("Registry rejected sync command.");
            return await response.json();
        } catch (e) {
            console.error("Sync Error:", e);
            alert("Registry Connection Error: Ensure backend is active and token is valid.");
            return null;
        } finally {
            showLoading(false);
        }
    }

    // --- Lifecycle Actions ---

    async function secureRevoke(fidId, pId) {
        const f = state.fiduciaries.find(f => f.id === fidId);
        const p = f.consents.find(c => c.id === pId);

        const result = await syncWithBackend(f.id, f.uid, f.sync_token, f.sync_url, {
            command: "REVOKE_PURPOSE",
            purpose_id: pId
        });

        if (result && result.success) {
            p.status = 'WITHDRAWN';
            f.audit.push({ phase: 'MAINTENANCE', action: `Revoked: ${p.name}`, time: 'Just now', actor: 'WALLET', status: 'SYNC_OK' });
            renderDetails();
        }
    }

    async function secureGrantConsent(fidId) {
        const f = state.fiduciaries.find(f => f.id === fidId);
        const checks = document.querySelectorAll('.grant-consent-chk');
        const dataPointConsents = Array.from(checks).map(chk => ({
            data_point_id: chk.value,
            consent_granted: chk.checked,
            purpose_agreed_to: chk.dataset.name,
            timestamp_updated: new Date().toISOString()
        }));

        const result = await syncWithBackend(f.id, f.uid, f.sync_token, f.sync_url, {
            command: "GRANT_CONSENT",
            policy_id: f.policy_id,
            data_point_consents: dataPointConsents
        });

        if (result && result.success) {
            const purposeMeta = new Map((f.pendingPurposes || []).map(p => [p.id, p]));
            f.status = 'IDLE';
            f.consents = dataPointConsents.map(c => ({
                id: c.data_point_id,
                name: c.purpose_agreed_to,
                status: c.consent_granted ? 'GRANTED' : 'WITHDRAWN',
                mandatory: (purposeMeta.get(c.data_point_id) || {}).is_mandatory_for_service || false
            }));
            f.audit.push({ phase: 'COLLECTION', action: 'Consent Provided via Wallet', time: 'Just now', actor: 'WALLET', status: 'SYNC_OK' });
            renderDetails();
        } else {
            alert('Failed to record consent. Please try again.');
        }
    }

    async function secureErasure(fidId) {
        const f = state.fiduciaries.find(f => f.id === fidId);

        const result = await syncWithBackend(f.id, f.uid, f.sync_token, f.sync_url, {
            command: "GLOBAL_ERASURE"
        });

        if (result && result.success) {
            f.status = 'TERMINATED';
            f.audit.push({ phase: 'ERASURE', action: 'Lifecycle Terminated Successfully', time: 'Just now', actor: 'USER:WALLET', status: 'PURGED' });
            f.consents.forEach(c => c.status = 'ERASED');
            renderDetails();
        }
    }

    // --- UI Logic ---

    function switchView(viewName) {
        document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
        document.getElementById('view-' + viewName).classList.remove('hidden');

        document.getElementById('nav-vault').classList.remove('text-teal-700', 'text-slate-300');
        document.getElementById('nav-history').classList.remove('text-teal-700', 'text-slate-300');
        document.getElementById('nav-vault').classList.add(viewName === 'vault' || viewName === 'details' ? 'text-teal-700' : 'text-slate-300');
        document.getElementById('nav-history').classList.add(viewName === 'history' ? 'text-teal-700' : 'text-slate-300');

        if (viewName === 'vault') renderVault();
        if (viewName === 'history') renderAudit();
    }

    function renderVault() {
        const list = document.getElementById('fiduciary-list');
        list.innerHTML = '';
        const empty = document.getElementById('empty-state');

        if (state.fiduciaries.length === 0) { empty.classList.remove('hidden'); return; }
        empty.classList.add('hidden');

        state.fiduciaries.forEach(f => {
            const card = document.createElement('div');
            card.className = "bg-white p-5 rounded-[28px] border border-slate-200 shadow-sm flex items-center justify-between cursor-pointer hover:border-teal-400 active:scale-95 transition-all group";
            card.onclick = () => { state.activeFidId = f.id; renderDetails(); switchView('details'); };
            const statusLabel = f.status === 'NO_CONSENT' ? 'ACTION NEEDED' : f.status;
            const statusColor = f.status === 'IDLE' ? 'bg-green-100 text-green-700'
                : (f.status === 'TERMINATED' ? 'bg-slate-100 text-slate-400'
                : (f.status === 'NO_CONSENT' ? 'bg-amber-100 text-amber-700' : 'bg-amber-100 text-amber-700'));
            const personaText = (f.personas && f.personas.length) ? f.personas.map(personaLabel).join(', ') : null;
            card.innerHTML = `
                <div class="flex items-center gap-4">
                    <div class="w-12 h-12 bg-slate-50 rounded-2xl flex items-center justify-center text-slate-300 group-hover:text-teal-600 transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M3 7v1a3 3 0 0 0 6 0v-1m0 1a3 3 0 0 0 6 0v-1m0 1a3 3 0 0 0 6 0v-1m0 1a3 3 0 0 0 6 0v-1"/><path d="M19 21V7H5v14"/><path d="M7 21v-4a2 2 0 0 1 4 0v4"/><path d="M13 21v-4a2 2 0 0 1 4 0v4"/></svg></div>
                    <div>
                        <h3 class="font-black text-sm text-slate-800 tracking-tight">${esc(f.name)}</h3>
                        <div class="flex items-center gap-2 mt-0.5 flex-wrap">
                            <span class="text-[7px] font-black uppercase px-1.5 py-0.5 rounded ${statusColor}">${esc(statusLabel)}</span>
                            ${personaText ? `<span class="text-[8px] font-black text-teal-600 uppercase">${esc(personaText)}</span><span class="text-slate-200">&middot;</span>` : ''}
                            <span class="text-[9px] text-slate-400 font-bold">${f.consents.filter(c => c.status === 'GRANTED').length} Active Purposes</span>
                        </div>
                    </div>
                </div>
            `;
            list.appendChild(card);
        });
    }

    async function renderDetails() {
        const f = state.fiduciaries.find(fid => fid.id === state.activeFidId);
        if (!f) return;
        const isTerminated = f.status === 'TERMINATED';
        const noConsent = f.status === 'NO_CONSENT';

        document.getElementById('details-sync-url').textContent = f.sync_url;
        const personaBadge = (f.personas && f.personas.length)
            ? `<span class="inline-block mt-2 text-[8px] font-black uppercase tracking-widest bg-teal-50 text-teal-700 px-2 py-1 rounded-lg">Persona: ${esc(f.personas.map(personaLabel).join(', '))}</span>`
            : '';
        document.getElementById('details-header').innerHTML = `
            <h2 class="text-2xl font-black text-slate-800 tracking-tight leading-tight">${esc(f.name)}</h2>
            ${f.policyTitle ? `<p class="text-[11px] text-slate-500 font-bold mt-1">${esc(f.policyTitle)}</p>` : ''}
            ${personaBadge}
            <p class="text-[10px] text-slate-400 font-black uppercase mt-2">Verification Token: <span class="text-teal-600">${esc(f.sync_token ? f.sync_token.substring(0, 12) : 'HANDOVER')}...</span></p>`;

        if (noConsent) {
            await renderNoConsentPanel(f);
            return;
        }

        const consentsList = document.getElementById('details-consents');
        consentsList.innerHTML = `<div class="p-4 bg-slate-50 flex justify-between items-center"><span class="text-[10px] font-black text-slate-400 uppercase tracking-widest">Purpose Allowances</span></div>`;
        f.consents.forEach(c => {
            const row = document.createElement('div');
            row.className = "p-4 flex justify-between items-start";
            const canRevoke = !isTerminated && !c.mandatory && c.status === 'GRANTED' && f.status === 'IDLE';
            row.innerHTML = `<div class="max-w-[70%]"><p class="text-xs font-black text-slate-800">${esc(c.name)}</p><p class="text-[10px] text-slate-400 mt-1 italic leading-tight">Current Status: ${esc(c.status)}</p></div><div class="flex flex-col items-end gap-2"><span class="text-[8px] font-black px-1.5 py-0.5 rounded uppercase ${c.status === 'GRANTED' ? 'bg-green-100 text-green-700' : 'bg-red-50 text-red-600'}">${esc(c.status)}</span>${canRevoke ? `<button data-fid="${esc(f.id)}" data-cid="${esc(c.id)}" class="revoke-btn text-[9px] font-black text-red-500 hover:underline tracking-tighter">REVOKE RIGHTS</button>` : ''}</div>`;
            if (canRevoke) {
                const btn = row.querySelector('.revoke-btn');
                if (btn) btn.addEventListener('click', () => secureRevoke(btn.dataset.fid, btn.dataset.cid));
            }
            consentsList.appendChild(row);
        });

        const actionsArea = document.getElementById('management-actions');
        if (isTerminated) {
            actionsArea.innerHTML = `
                <div class="p-6 bg-slate-100 rounded-[36px] text-slate-500 border border-slate-200 flex flex-col items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="text-green-600 mb-2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <h4 class="text-sm font-black mb-1 uppercase tracking-tight">ERASURE COMPLETED</h4>
                    <p class="text-[10px] text-center px-4 leading-tight">Data principal lifecycle has been terminated in the registry. Processing is blocked.</p>
                </div>
            `;
        } else {
            actionsArea.innerHTML = `
                <div class="p-6 bg-red-600 rounded-[32px] text-white shadow-xl shadow-red-200 relative overflow-hidden group">
                    <h4 class="text-sm font-black mb-1 text-center uppercase tracking-tight">Global Erasure Request</h4>
                    <p class="text-[10px] text-red-100 leading-tight mb-5 text-center px-4">Permanently terminate data processing and trigger hard-purge.</p>
                    <button data-fid="${esc(f.id)}" class="erasure-btn w-full py-4 rounded-2xl font-black uppercase tracking-widest text-[11px] bg-white text-red-600 hover:shadow-2xl transition-all">Initiate Hard Purge</button>
                </div>
            `;
            const erasureBtn = actionsArea.querySelector('.erasure-btn');
            if (erasureBtn) erasureBtn.addEventListener('click', () => secureErasure(erasureBtn.dataset.fid));
        }
    }

    /**
     * Renders a first-time consent-collection form in place of the (empty) purpose list, for
     * fiduciaries where GET_CONSENT_DETAILS reported no active consent yet. Fetches the policy's
     * purposes on first view and caches them on the fiduciary entry.
     */
    async function renderNoConsentPanel(f) {
        const consentsList = document.getElementById('details-consents');
        const actionsArea = document.getElementById('management-actions');

        if (!f.pendingPurposes) {
            consentsList.innerHTML = `<div class="p-6 text-center text-[10px] text-slate-400 font-black uppercase tracking-widest">Loading purposes...</div>`;
            actionsArea.innerHTML = '';

            if (!f.policy_id) {
                consentsList.innerHTML = `<div class="p-6 text-center text-[10px] text-red-500 font-black uppercase tracking-widest leading-relaxed">This artifact has no policy reference.<br/>Re-download or re-scan a fresh PCA from your dashboard.</div>`;
                return;
            }

            const result = await syncWithBackend(f.id, f.uid, f.sync_token, f.sync_url, {
                command: "GET_POLICY_PURPOSES",
                policy_id: f.policy_id
            });
            if (!result || !result.success) {
                const reason = (result && result.message) ? result.message : 'Could not load policy purposes.';
                consentsList.innerHTML = `<div class="p-6 text-center text-[10px] text-red-500 font-black uppercase tracking-widest">${esc(reason)}</div>`;
                return;
            }
            f.pendingPurposes = result.purposes || [];
            if (!f.policyTitle) f.policyTitle = result.policy_title;
            if (!f.personas || f.personas.length === 0) f.personas = result.personas || [];
        }

        consentsList.innerHTML = `<div class="p-4 bg-slate-50 flex justify-between items-center"><span class="text-[10px] font-black text-slate-400 uppercase tracking-widest">Select Purposes</span></div>`;
        f.pendingPurposes.forEach(p => {
            const row = document.createElement('div');
            row.className = "p-4 flex justify-between items-start gap-3";
            row.innerHTML = `
                <div class="max-w-[70%]">
                    <p class="text-xs font-black text-slate-800">${esc(p.name)}</p>
                    <p class="text-[10px] text-slate-400 mt-1 italic leading-tight">${esc(p.description || '')}</p>
                    ${p.is_mandatory_for_service ? '<p class="text-[8px] font-black text-amber-600 uppercase mt-1">Required for service</p>' : ''}
                </div>
                <input type="checkbox" class="grant-consent-chk w-5 h-5 accent-teal-700 mt-1 shrink-0" value="${esc(p.id)}" data-name="${esc(p.name)}" ${p.is_mandatory_for_service ? 'checked disabled' : ''}>
            `;
            consentsList.appendChild(row);
        });

        actionsArea.innerHTML = `
            <div class="p-6 bg-teal-700 rounded-[32px] text-white shadow-xl shadow-teal-100">
                <h4 class="text-sm font-black mb-1 text-center uppercase tracking-tight">Provide Consent</h4>
                <p class="text-[10px] text-teal-100 leading-tight mb-5 text-center px-4">No active consent yet with ${esc(f.name)}. Choose your preferences and confirm.</p>
                <button data-fid="${esc(f.id)}" class="grant-btn w-full py-4 rounded-2xl font-black uppercase tracking-widest text-[11px] bg-white text-teal-700 hover:shadow-2xl transition-all">Grant Consent</button>
            </div>
        `;
        const grantBtn = actionsArea.querySelector('.grant-btn');
        if (grantBtn) grantBtn.addEventListener('click', () => secureGrantConsent(grantBtn.dataset.fid));
    }

    function renderAudit() {
        const list = document.getElementById('audit-trail-list');
        list.innerHTML = '';
        state.fiduciaries.forEach(f => {
            const header = document.createElement('div');
            header.innerHTML = `<p class="text-[9px] font-black text-teal-600 uppercase tracking-widest mb-4">Origin: ${esc(f.name)}</p>`;
            list.appendChild(header);
            f.audit.slice().reverse().forEach(log => {
                const entry = document.createElement('div');
                entry.className = "relative mb-6";
                entry.innerHTML = `<div class="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full ring-4 ring-slate-50 ${log.phase === 'ERASURE' ? 'bg-red-500' : 'bg-teal-500'}"></div><div class="bg-white p-4 rounded-2xl border border-slate-100 shadow-sm transition-all hover:border-teal-200"><div class="flex justify-between items-start mb-2"><span class="text-[7px] font-black bg-slate-100 text-slate-500 px-2 py-0.5 rounded uppercase">${esc(log.phase)}</span><span class="text-[8px] text-slate-400 font-mono">${esc(log.time)}</span></div><p class="text-[10px] font-bold text-slate-700 leading-tight">${esc(log.action)}</p><div class="flex items-center justify-between mt-3 pt-2 border-t border-slate-50"><span class="text-[8px] text-slate-400 font-black uppercase tracking-widest flex items-center gap-1">ACTOR: ${esc(log.actor)}</span><span class="text-[8px] font-black text-teal-600 uppercase italic">${esc(log.status)}</span></div></div>`;
                list.appendChild(entry);
            });
        });
    }

    // --- File & Handover Handlers ---

    function triggerFileInput() { document.getElementById('file-input').click(); }

    function handleFileSelect(e) {
        const file = e.target.files[0];
        if (!file) return;
        showLoading(true);
        const reader = new FileReader();
        reader.onload = async (event) => {
            try {
                const data = JSON.parse(event.target.result);
                const fidId = data.fid || data.id;
                const userId = data.uid || data.user_id;
                const syncToken = data.token || data.sync_token;
                const syncUrl = data.sync_url || WALLET_API;
                const policyId = data.policy_id || null;

                if (!fidId || !syncToken || !userId) throw new Error("Invalid PCA: Missing context tokens or UID.");

                // 1. FETCH FIDUCIARY NAME (Utility in Wallet.java)
                const nameRes = await fetch(syncUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: "GET_FIDUCIARY_NAME", fiduciary_id: fidId })
                });
                const nameData = await nameRes.json();
                const realName = nameData.fiduciary_name || fidId;

                // 2. FETCH AUTHORITATIVE CONSENT DETAILS FROM SERVER (FRESH SYNC)
                // policy_id is passed through so the registry can resolve the policy's title and
                // persona (data_subject_categories) even when there's no active consent yet.
                const detailRes = await syncWithBackend(fidId, userId, syncToken, syncUrl, { command: "GET_CONSENT_DETAILS", policy_id: policyId });
                if (!detailRes) throw new Error("Registry unreachable. Ensure backend is active.");

                // No active consent just means nothing has been granted (or it was withdrawn) --
                // it is NOT the same as a terminated relationship. The wallet offers a first-time
                // "Provide Consent" flow for this case instead of a dead-end status.
                const noActiveConsent = !detailRes.success;
                const rawConsents = detailRes.data_point_consents || (data.consents ? data.consents : {});
                const mappedConsents = Array.isArray(rawConsents) ? rawConsents.map(c => ({
                    id: pointPurposeId(c),
                    name: c.purpose_agreed_to || c.name,
                    status: noActiveConsent ? 'WITHDRAWN' : (pointGranted(c) ? 'GRANTED' : 'WITHDRAWN'),
                    mandatory: c.is_mandatory || false
                })) : [];

                const newFid = {
                    id: fidId,
                    uid: userId,
                    name: realName,
                    status: noActiveConsent ? 'NO_CONSENT' : 'IDLE',
                    sync_url: syncUrl,
                    sync_token: syncToken,
                    policy_id: detailRes.policy_id || policyId,
                    policyTitle: detailRes.policy_title || null,
                    personas: detailRes.personas || [],
                    pendingPurposes: null,
                    consents: mappedConsents,
                    audit: [{ phase: 'COLLECTION', action: noActiveConsent ? 'PCA Imported — No Consent Provided Yet' : 'PCA Imported & Registry Synced', time: 'Just now', actor: 'WALLET', status: noActiveConsent ? 'PENDING_CONSENT' : 'VERIFIED' }]
                };

                state.fiduciaries.push(newFid);
                renderVault();
                showLoading(false);
            } catch (err) { alert("Security Error: " + err.message); showLoading(false); }
        };
        reader.readAsText(file);
    }

    function simulateScan() {
        // Simulation of QR Handshake carrying Fid and Token
        const mockScan = new Blob([JSON.stringify({
            fid: 'fiduciary_hub_abc',
            uid: 'rahul@example.com',
            token: 'SECURE_JWT_TOKEN_' + Math.random().toString(36).substring(7),
            sync_url: WALLET_API,
            policy_id: 'demo_policy_v1'
        })], { type: 'application/json' });

        handleFileSelect({ target: { files: [mockScan] } });
    }

    function showLoading(show) { document.getElementById('loading-spinner').classList.toggle('hidden', !show); }
    window.onload = () => renderVault();
