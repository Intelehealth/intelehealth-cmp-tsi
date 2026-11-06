// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        togglePcaPopover: () => togglePcaPopover(),
        downloadPCA: () => downloadPCA(),
        setTab: (el) => setTab(el.getAttribute('data-arg')),
        closeDetailModal: () => { document.getElementById('detail-modal').style.display = 'none'; },
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
    // Tab bodies are re-rendered via innerHTML, so their controls use delegation on the
    // stable #tab-content container (data-tab-action / data-tab-change).
    const tabClickHandlers = {
        selectPolicy: (el) => selectPolicy(el.getAttribute('data-policy-id')),
        savePreferences: () => savePreferences(),
        applyHistoryFilters: () => applyHistoryFilters(),
        clearHistoryFilters: () => clearHistoryFilters(),
        downloadHistory: (el) => downloadHistory(el.getAttribute('data-format')),
        checkConsent: () => checkConsent(),
        toggleGrievanceForm: () => toggleGrievanceForm(),
        submitGrievance: () => submitGrievance(),
    };
    const tabContent = document.getElementById('tab-content');
    tabContent.addEventListener('click', (e) => {
        const el = e.target.closest('[data-tab-action]');
        if (!el || !tabContent.contains(el)) return;
        const fn = tabClickHandlers[el.getAttribute('data-tab-action')];
        if (fn) fn(el, e);
    });
    tabContent.addEventListener('change', (e) => {
        const el = e.target;
        if (el.getAttribute && el.getAttribute('data-tab-change') === 'changeLang') changeLang(el.value);
    });
})();

    // ── Session bootstrap ───────────────────────────────────────────────
    let SESSION = null;

    function handleLogout() {
        clearSession();
        window.location.href = 'index.html';
    }

    // ── Tab management ──────────────────────────────────────────────────
    const tabs = ['consent', 'history', 'grievance'];
    let activeTab = 'consent';

    function setTab(tab) {
        activeTab = tab;
        document.querySelectorAll('.tab-btn').forEach((btn, i) => {
            btn.classList.toggle('active', tabs[i] === tab);
        });
        loadTab(tab);
    }

    async function loadTab(tab) {
        const area = document.getElementById('tab-content');
        area.innerHTML = '<div class="spinner"><div class="spin-ring"></div><p>Loading...</p></div>';
        if (tab === 'consent')   await renderConsentTab(area);
        if (tab === 'history')   await renderHistoryTab(area);
        if (tab === 'grievance') await renderGrievanceTab(area);
    }

    // ── Tab 1: Manage Consent ───────────────────────────────────────────
    let currentPolicy = null;
    let currentLangContent = null;
    let currentLang = 'en';
    let activePolicyEntry = null; // the { policy_id, title, ... } currently shown

    async function renderConsentTab(area) {
        const policies = SESSION.policies || [];
        if (policies.length === 0) {
            area.innerHTML = '<p style="color:#64748b;text-align:center;padding:40px;">No active consent policy found for this organisation.</p>';
            return;
        }

        // SESSION.policies is already scoped to the declared persona (portal.js filters it at
        // login) -- this just picks which one is pre-selected among what's left.
        if (!activePolicyEntry || !policies.find(p => p.policy_id === activePolicyEntry.policy_id)) {
            const persona = (SESSION.persona || '').toLowerCase();
            const personaMatch = persona && policies.find(p => (p.personas || []).some(c => (c || '').toLowerCase() === persona));
            activePolicyEntry = personaMatch || policies[0];
        }

        // Render policy selector pills (only when there are multiple policies)
        let selectorHtml = '';
        if (policies.length > 1) {
            const pills = policies.map(p => {
                const isActive = p.policy_id === activePolicyEntry.policy_id;
                return `<button data-tab-action="selectPolicy" data-policy-id="${esc(p.policy_id)}" style="padding:6px 16px;border-radius:20px;font-size:0.8rem;font-weight:700;cursor:pointer;border:2px solid ${isActive ? 'var(--tsi-primary)' : '#e2e8f0'};background:${isActive ? 'var(--tsi-primary)' : 'white'};color:${isActive ? 'white' : '#475569'};transition:all 0.2s;">${esc(p.title || p.policy_id)}</button>`;
            }).join('');
            // Only claim we've scoped to the persona when every remaining policy actually
            // carries that tag -- if none matched, portal.js fell back to the unfiltered
            // list and this hint would otherwise overstate what happened.
            const personaLower = (SESSION.persona || '').toLowerCase();
            const allMatchPersona = personaLower && policies.every(p => (p.personas || []).some(c => (c || '').toLowerCase() === personaLower));
            const personaHint = allMatchPersona
                ? `<p style="font-size:0.7rem;color:#94a3b8;margin:6px 0 0;">Showing policies for: <strong style="color:#0891b2;">${esc(getPersonaLabel(SESSION.persona))}</strong> — you can still view any policy above.</p>`
                : '';
            selectorHtml = `
                <div style="margin-bottom:20px;">
                    <p style="font-size:0.7rem;font-weight:700;text-transform:uppercase;color:#94a3b8;margin:0 0 8px;">Select Policy</p>
                    <div style="display:flex;gap:8px;flex-wrap:wrap;">${pills}</div>
                    ${personaHint}
                </div>`;
        }

        area.innerHTML = selectorHtml + '<div id="preference-center-body"><div class="spinner"><div class="spin-ring"></div><p>Loading policy...</p></div></div>';

        await loadPolicyPreferenceCenter(activePolicyEntry.policy_id);
    }

    async function selectPolicy(policyId) {
        const policies = SESSION.policies || [];
        activePolicyEntry = policies.find(p => p.policy_id === policyId) || activePolicyEntry;
        // Re-render the full tab so selector pills update
        await renderConsentTab(document.getElementById('tab-content'));
    }

    async function loadPolicyPreferenceCenter(policyId) {
        const centerArea = document.getElementById('preference-center-body');
        if (!centerArea) return;

        const [policy, activeConsent] = await Promise.all([
            apiCall('/api/v1/client/policy', 'get_policy', { policy_id: policyId }),
            apiCall('/api/v1/client/consent', 'get_active_consent', {
                user_id: SESSION.userId,
                fiduciary_id: SESSION.fiduciaryId,
                policy_id: policyId
            })
        ]);

        if (!policy || !policy.policy_content) {
            centerArea.innerHTML = '<p style="color:#64748b;text-align:center;padding:40px;">Policy content unavailable. Please contact the organisation.</p>';
            return;
        }

        currentPolicy = policy;
        const policyMap = resolvePolicyContent(policy);
        currentLang = getPreferredLanguage(policyMap);
        currentLangContent = policyMap[currentLang];
        document.documentElement.lang = currentLang;

        let existingPrefs = {};
        if (activeConsent && activeConsent.data_point_consents) {
            const dpc = activeConsent.data_point_consents;
            if (Array.isArray(dpc)) {
                dpc.forEach(p => { existingPrefs[pointPurposeId(p)] = pointGranted(p); });
            } else if (typeof dpc === 'object') {
                Object.keys(dpc).forEach(k => { existingPrefs[purposeKey(k)] = pointGranted(dpc[k]); });
            }
        }

        renderPreferenceCenter(centerArea, policyMap, existingPrefs);
    }

    function renderPreferenceCenter(area, policyMap, existingPrefs) {
        const langs = Object.keys(policyMap);
        const lc = currentLangContent;
        if (!lc) { area.innerHTML = '<p style="color:#64748b;text-align:center;padding:40px;">Policy content unavailable.</p>'; return; }

        // CC-03: every purpose starts unticked unless the principal already chose
        // it, and none is locked. A purpose the service depends on is labelled as
        // such - declining it is the principal's choice to make, never a default.
        let purposeHtml = (lc.data_processing_purposes || []).map(p => {
            const key = purposeKey(p.id);
            const checked = existingPrefs[key] === true;
            return `
            <div class="toggle-row">
                <div style="flex:1;padding-right:16px;">
                    <div style="font-weight:700;font-size:0.875rem;color:#1e293b;">${esc(p.name)}</div>
                    <div class="purpose-desc">${esc(p.description || '')}</div>
                    ${p.is_mandatory_for_service ? '<span style="font-size:0.65rem;font-weight:800;text-transform:uppercase;color:#0891b2;">Needed to provide the service - you may still decline</span>' : ''}
                </div>
                <label class="toggle-switch">
                    <input type="checkbox" id="toggle-${esc(p.id)}" ${checked ? 'checked' : ''} aria-label="Consent to ${esc(p.name)}">
                    <span class="toggle-slider"></span>
                </label>
            </div>`;
        }).join('');

        let langOptions = langs.map(l => `<option value="${l}" ${l === currentLang ? 'selected' : ''}>${l.toUpperCase()}</option>`).join('');

        area.innerHTML = `
            <div id="save-success" class="success-banner">Your consent preferences have been saved.</div>

            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                <div>
                    <h2 style="margin:0;font-size:1rem;font-weight:700;color:#1e293b;">${esc(lc.title || 'Consent Preferences')}</h2>
                    <p style="margin:4px 0 0;font-size:0.8rem;color:#64748b;">${esc(lc.general_purpose_description || '')}</p>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="font-size:0.7rem;color:#64748b;font-weight:700;text-transform:uppercase;">Language:</span>
                    <select id="lang-select" style="font-size:0.8rem;padding:4px 8px;border:1px solid #cbd5e1;border-radius:6px;outline:none;" data-tab-change="changeLang">${langOptions}</select>
                </div>
            </div>

            <div id="purposes-list">${purposeHtml}</div>

            <div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap;">
                <button class="btn-primary" data-tab-action="savePreferences">Save My Preferences</button>
            </div>

            <div id="save-success-bottom" class="success-banner" style="margin-top:16px;margin-bottom:0;">Your consent preferences have been saved.</div>
        `;
    }

    function changeLang(lang) {
        const policyMap = resolvePolicyContent(currentPolicy);
        currentLang = lang;
        currentLangContent = policyMap[lang];
        document.documentElement.lang = lang;
        const prefs = getCurrentToggles();
        const area = document.getElementById('preference-center-body') || document.getElementById('tab-content');
        renderPreferenceCenter(area, policyMap, prefs);
    }

    // A record's kind comes from its status (the CMS sets consent_mechanism to how
    // the consent arrived, e.g. PRINCIPAL_PORTAL); older records carried it in the mechanism.
    function recordKind(rec) {
        const status = (rec && rec.consent_status_general) || '';
        const mech = (rec && rec.consent_mechanism) || '';
        if (status === 'ERASURE_REQUESTED' || mech === 'ERASURE_REQUEST') return 'ERASURE_REQUEST';
        if (status === 'WITHDRAWN' || status === 'PARTIAL_WITHDRAWAL' || mech === 'CONSENT_WITHDRAWN') return 'CONSENT_WITHDRAWN';
        return mech;
    }

    function getCurrentToggles() {
        const prefs = {};
        (currentLangContent.data_processing_purposes || []).forEach(p => {
            const el = document.getElementById('toggle-' + p.id);
            if (el) prefs[p.id] = el.checked;
        });
        return prefs;
    }

    async function savePreferences() {
        const prefs = getCurrentToggles();
        const purposes = currentLangContent.data_processing_purposes || [];
        // CC-03: the decision sent is exactly what the principal ticked.
        const dataPointConsents = purposes.map(p => ({
            data_point_id: p.id,
            consent_granted: prefs[p.id] === true,
            purpose_agreed_to: p.name,
            timestamp_updated: new Date().toISOString()
        }));
        const declinedNeeded = purposes.filter(p => p.is_mandatory_for_service && prefs[p.id] !== true);
        if (declinedNeeded.length > 0 && !confirm(
            'You have declined: ' + declinedNeeded.map(p => p.name).join(', ') +
            '. The service depends on this processing, so the parts of the service that need it cannot be provided. Save your choices?')) {
            return;
        }

        const result = await apiCall('/api/v1/client/consent', 'record_consent', {
            user_id: SESSION.userId,
            fiduciary_id: SESSION.fiduciaryId,
            policy_id: activePolicyEntry ? activePolicyEntry.policy_id : currentPolicy.policy_id,
            language_selected: currentLang,
            data_point_consents: dataPointConsents
        });

        const banners = [document.getElementById('save-success'), document.getElementById('save-success-bottom')].filter(Boolean);
        if (result && (result.success || result.consent_record_id || result.id)) {
            banners.forEach(banner => { banner.style.display = 'block'; });
            setTimeout(() => { banners.forEach(banner => { banner.style.display = 'none'; }); }, 4000);
        } else {
            banners.forEach(banner => {
                banner.style.display = 'block';
                banner.style.background = '#fef2f2';
                banner.style.color = '#b91c1c';
                banner.style.borderColor = '#fecaca';
                banner.textContent = 'Failed to save preferences. Please try again.';
            });
            setTimeout(() => {
                banners.forEach(banner => {
                    banner.style.display = 'none';
                    banner.style.background = '';
                    banner.style.color = '';
                    banner.style.borderColor = '';
                    banner.textContent = 'Your consent preferences have been saved.';
                });
            }, 5000);
        }
    }

    // ── Tab 2: Consent History (grouped by policy) ─────────────────────
    let historyCache = [];
    let policyPurposesForVerify = [];
    let historyPolicyMap = {}; // { policyId: [{id, name, is_mandatory}] }
    // UD-03: the principal can search and filter by purpose, date and status.
    let historyFilters = { purpose_id: '', status: '', start_date: '', end_date: '' };

    function historyFilterBar() {
        const purposeOptions = policyPurposesForVerify.map(p =>
            `<option value="${esc(p.id)}" ${purposeKey(historyFilters.purpose_id) === purposeKey(p.id) ? 'selected' : ''}>${esc(p.name)}</option>`
        ).join('');
        // UD-03: 'In force' is the server's ACTIVE filter (is_active_consent) - the
        // record currently in force, which may itself be a partial withdrawal.
        const statusOptions = [['', 'Any status'], ['ACTIVE', 'In force'], ['CONSENT_GIVEN', 'Consent given'],
                               ['PARTIAL_WITHDRAWAL', 'Partially withdrawn'], ['WITHDRAWN', 'Withdrawn'],
                               ['ERASURE_REQUESTED', 'Erasure requested']]
            .map(([v, l]) => `<option value="${v}" ${historyFilters.status === v ? 'selected' : ''}>${l}</option>`).join('');
        const field = 'padding:7px 10px;border:1px solid #cbd5e1;border-radius:6px;font-size:0.8rem;outline:none;';
        return `
            <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin:0 0 18px;">
                <label style="font-size:0.7rem;color:#64748b;font-weight:700;">Purpose<br>
                    <select id="hf-purpose" style="${field}"><option value="">Any purpose</option>${purposeOptions}</select></label>
                <label style="font-size:0.7rem;color:#64748b;font-weight:700;">Status<br>
                    <select id="hf-status" style="${field}">${statusOptions}</select></label>
                <label style="font-size:0.7rem;color:#64748b;font-weight:700;">From<br>
                    <input type="date" id="hf-start" value="${esc(historyFilters.start_date)}" style="${field}"></label>
                <label style="font-size:0.7rem;color:#64748b;font-weight:700;">To<br>
                    <input type="date" id="hf-end" value="${esc(historyFilters.end_date)}" style="${field}"></label>
                <button class="btn-primary" data-tab-action="applyHistoryFilters" style="padding:8px 14px;">Filter</button>
                <button data-tab-action="clearHistoryFilters" style="background:none;border:none;color:#64748b;font-weight:600;cursor:pointer;padding:8px 10px;">Clear</button>
                <span style="flex:1;"></span>
                <button data-tab-action="downloadHistory" data-format="csv" style="background:white;border:1px solid #cbd5e1;border-radius:6px;font-weight:700;font-size:0.8rem;cursor:pointer;padding:8px 12px;">Download CSV</button>
                <button data-tab-action="downloadHistory" data-format="pdf" style="background:white;border:1px solid #cbd5e1;border-radius:6px;font-weight:700;font-size:0.8rem;cursor:pointer;padding:8px 12px;">Download PDF</button>
            </div>`;
    }

    function applyHistoryFilters() {
        historyFilters = {
            purpose_id: document.getElementById('hf-purpose').value,
            status: document.getElementById('hf-status').value,
            start_date: document.getElementById('hf-start').value,
            end_date: document.getElementById('hf-end').value
        };
        renderHistoryTab(document.getElementById('tab-content'));
    }

    function clearHistoryFilters() {
        historyFilters = { purpose_id: '', status: '', start_date: '', end_date: '' };
        renderHistoryTab(document.getElementById('tab-content'));
    }

    // UD-04: the principal downloads their own consent history as CSV or PDF.
    async function downloadHistory(format) {
        const ok = await apiDownload('/api/v1/client/consent', 'export_consent_history', {
            user_id: SESSION.userId,
            format: format,
            language: currentLang || 'en'
        }, `consent-history.${format}`);
        if (!ok) alert('The download could not be prepared. Please try again.');
    }

    async function renderHistoryTab(area) {
        const historyQuery = { user_id: SESSION.userId, fiduciary_id: SESSION.fiduciaryId, limit: 100 };
        Object.entries(historyFilters).forEach(([k, v]) => {
            if (v) historyQuery[k] = k === 'end_date' ? v + 'T23:59:59' : v;
        });
        // Fetch history and all policy content in parallel
        const [historyResult, ...policyResults] = await Promise.all([
            apiCall('/api/v1/client/consent', 'list_consent_history', historyQuery),
            ...(SESSION.policies || []).map(p =>
                apiCall('/api/v1/client/policy', 'get_policy', { policy_id: p.policy_id })
            )
        ]);

        historyCache = Array.isArray(historyResult) ? historyResult : (historyResult && historyResult.data ? historyResult.data : []);

        // Build historyPolicyMap and policyPurposesForVerify from fetched policy content
        historyPolicyMap = {};
        const verifyPurposesSeen = new Map();
        (SESSION.policies || []).forEach((p, i) => {
            const policy = policyResults[i];
            if (!policy) return;
            const policyMap = resolvePolicyContent(policy); // handles string or object policy_content
            if (!policyMap || typeof policyMap !== 'object') return;
            const langContent = policyMap[currentLang || 'en'] || policyMap['en'] || Object.values(policyMap)[0];
            if (!langContent) return;
            const purposes = (langContent.data_processing_purposes || []).map(dp => ({
                id: dp.id,
                name: dp.name,
                is_mandatory: !!dp.is_mandatory_for_service
            }));
            historyPolicyMap[p.policy_id] = purposes;
            purposes.forEach(dp => {
                if (!verifyPurposesSeen.has(dp.id)) verifyPurposesSeen.set(dp.id, dp.name);
            });
        });
        policyPurposesForVerify = Array.from(verifyPurposesSeen.entries()).map(([id, name]) => ({ id, name }));

        // Refresh QR now that we have sync_token from the latest consent record
        // Deferred so QR failure never blocks tab rendering
        if (historyCache.length > 0 && SESSION.pcaQrEnabled !== false) setTimeout(updateQR, 0);

        if (historyCache.length === 0) {
            const filtered = Object.values(historyFilters).some(Boolean);
            area.innerHTML = `${historyFilterBar()}<div style="text-align:center;padding:60px 20px;color:#94a3b8;">
                <p style="font-size:1rem;font-weight:600;">No consent records found.</p>
                <p style="font-size:0.875rem;">${filtered ? 'No record matches these filters.' : 'Your consent records will appear here once you save preferences.'}</p>
            </div>${renderSelfVerify()}`;
            return;
        }

        // Group records by policy_id (preserving insertion order = most-recent first)
        const grouped = {};
        historyCache.forEach(rec => {
            if (!grouped[rec.policy_id]) grouped[rec.policy_id] = [];
            grouped[rec.policy_id].push(rec);
        });

        // Build HTML: one section per policy
        let sectionsHtml = '';
        for (const [policyId, records] of Object.entries(grouped)) {
            const policyTitle = getPolicyTitle(policyId) || policyId;
            // Find the most-recent active record for this policy to determine eligibility
            const latestActive = records.find(r => r.is_active_consent) || records[0];
            const mechanism = recordKind(latestActive);
            // canWithdraw: record must be active and not a full erasure
            const canWithdraw = latestActive.is_active_consent === true && mechanism !== 'ERASURE_REQUEST';
            const canErasure  = mechanism !== 'ERASURE_REQUEST';

            const btnId = 'pid-' + policyId.replace(/[^a-zA-Z0-9]/g, '_');

            let rows = records.map(rec => {
                const mech = recordKind(rec);
                let displayStatus;
                if (mech === 'ERASURE_REQUEST') {
                    displayStatus = 'ERASURE_REQUEST';
                } else if (mech === 'CONSENT_WITHDRAWN') {
                    const dpc = Array.isArray(rec.data_point_consents)
                        ? rec.data_point_consents
                        : Object.values(rec.data_point_consents || {});
                    const allWithdrawn = dpc.length > 0 && dpc.every(p => !pointGranted(p));
                    displayStatus = allWithdrawn ? 'WITHDRAWN' : 'PARTIALLY WITHDRAWN';
                } else {
                    // UD-03: a consent record replaced by a later one (a re-consent,
                    // a withdrawal) is no longer in force; badging it ACTIVE made
                    // the 'In force' filter look as if it dropped active records.
                    displayStatus = rec.is_active_consent === true ? 'ACTIVE' : 'SUPERSEDED';
                }
                return `<tr>
                    <td style="font-family:monospace;font-size:0.7rem;color:#94a3b8;">...${esc(rec.id.slice(-6))}</td>
                    <td style="color:#64748b;">${esc(formatTimestamp(rec.timestamp))}</td>
                    <td style="color:#64748b;font-size:0.8rem;font-style:italic;">${esc(mech.replace(/_/g,' '))}</td>
                    <td>${getStatusBadge(displayStatus)}</td>
                    <td><button class="btn-link view-detail-btn" data-rid="${esc(rec.id)}">Details</button></td>
                </tr>`;
            }).join('');

            sectionsHtml += `
                <div style="margin-bottom:28px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:14px 16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px 10px 0 0;border-bottom:none;">
                        <div>
                            <div style="font-size:0.875rem;font-weight:700;color:#1e293b;">${esc(policyTitle)}</div>
                            <div style="font-size:0.7rem;font-family:monospace;color:#94a3b8;margin-top:2px;">${esc(policyId)}</div>
                        </div>
                        <div style="display:flex;gap:8px;">
                            <button class="btn-warn withdraw-policy-btn"
                                data-policy-id="${esc(policyId)}" data-policy-title="${esc(policyTitle)}"
                                id="w-${esc(btnId)}"
                                ${canWithdraw ? '' : 'disabled'} style="${canWithdraw ? '' : 'opacity:0.4;cursor:not-allowed;'}">
                                Withdraw
                            </button>
                            <button class="btn-danger erasure-policy-btn"
                                data-policy-id="${esc(policyId)}" data-policy-title="${esc(policyTitle)}"
                                id="e-${esc(btnId)}"
                                ${canErasure ? '' : 'disabled'} style="${canErasure ? '' : 'opacity:0.4;cursor:not-allowed;'}">
                                Erasure Request
                            </button>
                        </div>
                    </div>
                    <div style="overflow-x:auto;border:1px solid #e2e8f0;border-radius:0 0 10px 10px;">
                        <table class="dash-table">
                            <thead><tr>
                                <th>Ref</th><th>Timestamp</th><th>Mechanism</th><th>Status</th><th>Action</th>
                            </tr></thead>
                            <tbody>${rows}</tbody>
                        </table>
                    </div>
                </div>`;
        }

        area.innerHTML = `
            <h2 style="margin:0 0 6px;font-size:1rem;font-weight:700;color:#1e293b;">Consent History</h2>
            <p style="margin:0 0 20px;font-size:0.8rem;color:#64748b;">Records are grouped by consent policy. Use Withdraw or Erasure Request to act on a specific policy.</p>
            ${historyFilterBar()}
            ${sectionsHtml}
            <p style="font-size:0.7rem;color:#94a3b8;margin-top:4px;font-style:italic;">* Mandatory data is retained until account closure.</p>
            ${renderSelfVerify()}
        `;

        area.querySelectorAll('.view-detail-btn').forEach(btn => {
            btn.addEventListener('click', () => viewConsentDetail(btn.dataset.rid));
        });
        area.querySelectorAll('.withdraw-policy-btn').forEach(btn => {
            btn.addEventListener('click', () => openWithdrawModal(btn.dataset.policyId, btn.dataset.policyTitle));
        });
        area.querySelectorAll('.erasure-policy-btn').forEach(btn => {
            btn.addEventListener('click', () => erasureRequest(btn.dataset.policyId, btn.dataset.policyTitle));
        });
    }

    function renderSelfVerify() {
        const options = policyPurposesForVerify.map(p =>
            `<option value="${esc(p.id)}">${esc(p.name)}</option>`
        ).join('');
        const hasOptions = policyPurposesForVerify.length > 0;
        return `
            <div class="verify-box" style="margin-top:20px;">
                <h3 style="margin:0 0 8px;font-size:0.875rem;font-weight:700;color:#1e293b;">Verify My Consent for a Purpose</h3>
                <p style="margin:0 0 14px;font-size:0.8rem;color:#64748b;">Check whether your consent is currently active for a specific data processing purpose.</p>
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
                    ${hasOptions
                        ? `<select id="verify-purpose" style="padding:9px 12px;border:1px solid #cbd5e1;border-radius:6px;font-size:0.875rem;outline:none;">${options}</select>`
                        : `<input type="text" id="verify-purpose-text" placeholder="Enter Purpose ID" style="padding:9px 12px;border:1px solid #cbd5e1;border-radius:6px;font-size:0.875rem;width:220px;outline:none;">`
                    }
                    <button class="btn-primary" data-tab-action="checkConsent" style="padding:9px 16px;">Check Status</button>
                </div>
                <div id="verify-result"></div>
            </div>
        `;
    }

    async function checkConsent() {
        const selectEl = document.getElementById('verify-purpose');
        const inputEl  = document.getElementById('verify-purpose-text');
        const purposeId = selectEl ? selectEl.value : (inputEl ? inputEl.value.trim() : '');
        if (!purposeId) return;

        const result = await apiCall('/api/v1/client/consent', 'validate_consent', {
            user_id: SESSION.userId,
            fiduciary_id: SESSION.fiduciaryId,
            required_purpose_id: purposeId
        });

        const container = document.getElementById('verify-result');
        // P9-06: validate_consent answers with `valid` and metadata.purpose_status;
        // there is no `consent_granted` key on the response.
        const state = result && result.metadata ? result.metadata.purpose_status : null;
        if (result && result.valid === true) {
            container.innerHTML = `<div class="verify-result verify-granted">✓ Consent Active — you have granted consent for this purpose.</div>`;
        } else if (state === 'PURPOSE_CLOSED') {
            container.innerHTML = `<div class="verify-result verify-denied">✕ Purpose Ended — this purpose has been closed and no longer runs on your consent.</div>`;
        } else if (state === 'WITHDRAWN') {
            container.innerHTML = `<div class="verify-result verify-denied">✕ Consent Withdrawn — you have withdrawn consent for this purpose.</div>`;
        } else {
            container.innerHTML = `<div class="verify-result verify-denied">✕ No Active Consent — consent has not been granted for this purpose.</div>`;
        }
    }

    async function viewConsentDetail(recordId) {
        const rec = await apiCall('/api/v1/client/consent', 'get_consent_record_details', { record_id: recordId });
        if (!rec || !rec.id) return;

        document.getElementById('modal-record-ref').textContent = 'Record: ' + rec.id;
        const isWithdrawal = recordKind(rec) === 'CONSENT_WITHDRAWN';
        const isErasure    = recordKind(rec) === 'ERASURE_REQUEST';

        const dpc = rec.data_point_consents || {};
        let purposeHtml = '';
        const entries = Array.isArray(dpc) ? dpc : Object.values(dpc);
        // UD-02 / DD-01: each purpose row also shows its lifecycle state and the
        // governing retention period, the substitute for the BRD's expiry date
        // under the open-ended-consent decision.
        const statesById = {};
        (rec.purpose_states || []).forEach(s => { statesById[purposeKey(s.purpose_id)] = s; });
        entries.forEach(item => {
            // Use the actual per-purpose consent_granted value from the record.
            // Do NOT blanket-override to false — partial withdrawals have a mix of true/false.
            // P11-10: granted-ness and purpose read exactly as the server reads them.
            const granted = pointGranted(item);
            let label = granted ? '✓ GRANTED' : (isErasure ? '✕ ERASED' : isWithdrawal ? '✕ WITHDRAWN' : '✕ DENIED');
            let color = granted ? '#15803d' : '#b91c1c';
            const pid = pointPurposeId(item);
            const state = statesById[pid];
            // P7-06: lifecycle states are OPEN/CLOSED (purpose_lifecycle), and a
            // CLOSED purpose is the temporal fact DD-01 substitutes for expiry.
            const stateHtml = state && state.state && String(state.state).toUpperCase() === 'CLOSED'
                ? `<span style="font-size:0.65rem;font-weight:800;color:#b45309;border:1px solid #f59e0b;border-radius:4px;padding:2px 6px;margin-left:6px;text-transform:uppercase;">${esc(state.state)}</span>` : '';
            const retentionHtml = state && state.retention_period_days
                ? `<span style="font-size:0.62rem;color:#64748b;margin-left:6px;white-space:nowrap;">retention ${esc(state.retention_period_days)} days</span>` : '';
            purposeHtml += `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;margin-bottom:8px;">
                <span style="font-weight:700;font-size:0.8rem;color:#1e293b;">${esc(item.purpose_agreed_to || pid)}${stateHtml}${retentionHtml}</span>
                <span style="font-weight:800;font-size:0.75rem;color:${color};">${label}</span>
            </div>`;
        });

        document.getElementById('modal-purposes').innerHTML = purposeHtml || '<p style="color:#94a3b8;font-size:0.8rem;">No purpose data available.</p>';
        document.getElementById('modal-provenance').innerHTML = `
            <p><strong>Policy:</strong> ${esc(rec.policy_id)} v${esc(rec.policy_version)}</p>
            <p><strong>Mechanism:</strong> ${esc(rec.consent_mechanism)}</p>
            <p><strong>Timestamp:</strong> ${esc(formatTimestamp(rec.timestamp))}</p>
            <p><strong>Session IP:</strong> ${esc(rec.ip_address || 'Encrypted')}</p>
        `;
        document.getElementById('detail-modal').style.display = 'flex';
    }

    function openWithdrawModal(policyId, policyTitle) {
        // Find the most-recent active record for this policy
        const records = historyCache.filter(r => r.policy_id === policyId);
        const latestActive = records.find(r => r.is_active_consent) || records[0];
        if (!latestActive) return;

        const dpc = Array.isArray(latestActive.data_point_consents)
            ? latestActive.data_point_consents
            : Object.values(latestActive.data_point_consents || {});

        const policyPurposes = historyPolicyMap[policyId] || [];

        // All purposes are eligible for withdrawal (including mandatory)
        const eligible = dpc.map(dp => {
            const dpId = pointPurposeId(dp);
            const pInfo = policyPurposes.find(p => purposeKey(p.id) === purposeKey(dpId));
            return {
                id: dpId,
                name: dp.purpose_agreed_to || (pInfo && pInfo.name) || dpId,
                active: pointGranted(dp),
                mandatory: pInfo ? pInfo.is_mandatory : false
            };
        });

        const modal = document.getElementById('withdraw-modal');
        document.getElementById('withdraw-modal-title').textContent = policyTitle || policyId;
        modal.dataset.policyId = policyId;

        const listEl = document.getElementById('withdraw-purpose-list');
        if (eligible.length === 0) {
            listEl.innerHTML = '<p style="color:#94a3b8;font-size:0.85rem;text-align:center;padding:12px;">No eligible purposes found for withdrawal.</p>';
        } else {
            listEl.innerHTML = eligible.map(p => `
                <label style="display:flex;align-items:flex-start;gap:10px;padding:10px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;margin-bottom:8px;cursor:${p.active ? 'pointer' : 'default'};opacity:${p.active ? '1' : '0.55'};">
                    <input type="checkbox" class="withdraw-purpose-chk" value="${esc(p.id)}"
                        ${p.active ? 'checked' : 'disabled'}
                        style="margin-top:2px;width:15px;height:15px;accent-color:var(--tsi-primary);cursor:${p.active ? 'pointer' : 'not-allowed'};">
                    <span>
                        <span style="display:block;font-weight:700;font-size:0.85rem;color:#1e293b;">${esc(p.name)}</span>
                        <span style="font-size:0.7rem;color:${p.active ? (p.mandatory ? '#b45309' : '#15803d') : '#94a3b8'};">
                            ${p.active ? (p.mandatory ? 'Active · Required for service' : 'Active') : 'Already Withdrawn'}
                        </span>
                        ${p.active ? `<span class="withdraw-implication" data-purpose-id="${esc(p.id)}" style="display:block;margin-top:4px;font-size:0.72rem;color:#475569;"></span>` : ''}
                    </span>
                </label>
            `).join('');
        }

        // Select All toggle
        const selAllBtn = document.getElementById('withdraw-select-all');
        selAllBtn.textContent = 'Deselect All';
        selAllBtn.onclick = () => {
            const chks = modal.querySelectorAll('.withdraw-purpose-chk:not(:disabled)');
            const allChecked = Array.from(chks).every(c => c.checked);
            chks.forEach(c => { c.checked = !allChecked; });
            selAllBtn.textContent = allChecked ? 'Select All' : 'Deselect All';
        };

        modal.style.display = 'flex';
        loadWithdrawalImplications(policyId, listEl);
    }

    // CW-04: show what withdrawing each purpose means, and whether the law
    // requires the data to be kept anyway, BEFORE the principal confirms.
    async function loadWithdrawalImplications(policyId, listEl) {
        const result = await apiCall('/api/v1/client/consent', 'get_withdrawal_implications', {
            user_id: SESSION.userId,
            fiduciary_id: SESSION.fiduciaryId,
            policy_id: policyId,
            language: currentLang || 'en'
        });
        if (!result || !Array.isArray(result.purposes)) return;
        const byId = {};
        result.purposes.forEach(p => { byId[String(p.purpose_id).toLowerCase()] = p; });
        listEl.querySelectorAll('.withdraw-implication').forEach(el => {
            const info = byId[String(el.dataset.purposeId).toLowerCase()];
            if (!info) return;
            let text = esc(info.consequence || '');
            if (info.data_retained_by_law) {
                const days = info.retention_days ? ` for ${esc(String(info.retention_days))} days` : '';
                const ref = info.legal_reference ? ` (${esc(info.legal_reference)})` : '';
                text += `<br><strong style="color:#b45309;">Some data must be kept by law${days}${ref}.</strong>`;
            }
            el.innerHTML = text;
        });
    }

    async function withdrawConsent(policyId, purposeIds) {
        const body = { user_id: SESSION.userId, fiduciary_id: SESSION.fiduciaryId, language_selected: currentLang || 'en', reason: 'Withdrawn via My Privacy Dashboard.' };
        if (policyId) body.policy_id = policyId;
        if (purposeIds && purposeIds.length > 0) body.purpose_ids = purposeIds;
        const result = await apiCall('/api/v1/client/consent', 'withdraw_consent', body);
        if (result && result.success) {
            await renderHistoryTab(document.getElementById('tab-content'));
        } else {
            alert('Withdrawal request failed. Please try again.');
        }
    }

    async function erasureRequest(policyId, policyTitle) {
        const label = policyTitle ? `"${policyTitle}"` : 'the selected policy';
        if (!confirm(`Request COMPLETE erasure of your data under ${label}? This action is irreversible.`)) return;
        const body = { user_id: SESSION.userId, fiduciary_id: SESSION.fiduciaryId, language_selected: currentLang || 'en', reason: 'Erasure requested via My Privacy Dashboard.' };
        if (policyId) body.policy_id = policyId;
        const result = await apiCall('/api/v1/client/consent', 'erasure_request', body);
        if (result && result.success) {
            await renderHistoryTab(document.getElementById('tab-content'));
        } else {
            alert('Erasure request failed. Please try again.');
        }
    }

    // ── Tab 3: Requests & Grievances ────────────────────────────────────
    let showGrievanceForm = false;

    async function renderGrievanceTab(area) {
        const result = await apiCall('/api/v1/client/grievance', 'list_user_grievances', {
            user_id: SESSION.userId,
            fiduciary_id: SESSION.fiduciaryId
        });
        const list = Array.isArray(result) ? result : (result && result.data ? result.data : []);
        showGrievanceForm = false;
        renderGrievanceView(area, list);
    }

    function renderGrievanceView(area, list) {
        let rows = list.length === 0
            ? `<tr><td colspan="5" style="text-align:center;padding:40px;color:#94a3b8;font-style:italic;">No requests or grievances submitted yet.</td></tr>`
            : list.map(r => `<tr>
                <td style="font-family:monospace;font-size:0.75rem;color:#64748b;" title="${esc(r.grievance_id || r.id || '')}">${esc(r.reference_number || r.grievance_id || r.id)}</td>
                <td style="font-weight:700;font-size:0.8rem;color:#1e293b;">${esc((r.type||'').replace(/_/g,' '))}</td>
                <td style="color:#64748b;">${esc(r.subject)}</td>
                <td style="color:#64748b;">${esc(r.due_date ? formatTimestamp(r.due_date).split(',')[0] : 'N/A')}</td>
                <td>${getStatusBadge(r.status)}</td>
            </tr>`).join('');

        area.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                <div>
                    <h2 style="margin:0;font-size:1rem;font-weight:700;color:#1e293b;">Requests & Grievances</h2>
                    <p style="margin:4px 0 0;font-size:0.8rem;color:#64748b;">Your formal data rights requests and compliance inquiries.</p>
                </div>
                <button class="btn-primary" data-tab-action="toggleGrievanceForm" id="new-grievance-btn">+ New Request</button>
            </div>
            <div id="grievance-form-container" style="display:none;">
                <div class="grievance-form">
                    <h3 style="margin:0 0 20px;font-size:0.875rem;font-weight:700;color:#1e293b;">Submit a New Request</h3>
                    <label>Request Category</label>
                    <select id="g-type">
                        <option value="GENERAL_COMPLAINT">General Inquiry</option>
                        <option value="ERASURE_REQUEST">Right to Erasure (Deletion)</option>
                        <option value="DATA_ACCESS_REQUEST">Data Portability Request</option>
                        <option value="CORRECTION_REQUEST">Correction Request</option>
                    </select>
                    <label>Subject</label>
                    <input type="text" id="g-subject" placeholder="Brief summary of your request">
                    <label>Detailed Description</label>
                    <textarea id="g-description" rows="4" placeholder="Explain your request in detail..."></textarea>
                    <div style="display:flex;gap:10px;justify-content:flex-end;">
                        <button data-tab-action="toggleGrievanceForm" style="background:none;border:none;color:#64748b;font-weight:600;cursor:pointer;padding:10px 16px;">Cancel</button>
                        <button class="btn-primary" id="submit-grievance-btn" data-tab-action="submitGrievance">Submit Request</button>
                    </div>
                    <div id="g-error" style="display:none;color:#b91c1c;font-size:0.8rem;margin-top:10px;"></div>
                </div>
            </div>
            <div style="overflow-x:auto;">
                <table class="dash-table">
                    <thead><tr><th>Reference</th><th>Type</th><th>Subject</th><th>Deadline</th><th>Status</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    function toggleGrievanceForm() {
        showGrievanceForm = !showGrievanceForm;
        const fc = document.getElementById('grievance-form-container');
        const btn = document.getElementById('new-grievance-btn');
        if (fc) fc.style.display = showGrievanceForm ? 'block' : 'none';
        if (btn) btn.textContent = showGrievanceForm ? '✕ Cancel' : '+ New Request';
    }

    async function submitGrievance() {
        const type    = document.getElementById('g-type').value;
        const subject = document.getElementById('g-subject').value.trim();
        const desc    = document.getElementById('g-description').value.trim();
        const errEl   = document.getElementById('g-error');
        const btn     = document.getElementById('submit-grievance-btn');

        errEl.style.display = 'none';
        if (!subject || !desc) {
            errEl.textContent = 'Subject and description are required.';
            errEl.style.display = 'block';
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Submitting...';

        const result = await apiCall('/api/v1/client/grievance', 'submit_grievance', {
            user_id: SESSION.userId,
            fiduciary_id: SESSION.fiduciaryId,
            type, subject, description: desc,
            // GR-03: the grievance is recorded in the principal's chosen language.
            language: currentLang || 'en'
        });

        if (result && result.success) {
            await renderGrievanceTab(document.getElementById('tab-content'));
            // UD-10: give the principal the reference to quote in follow-up contact.
            const ref = result.reference_number || (result.data && result.data.reference_number);
            if (ref) alert('Your request was submitted. Your reference number is ' + ref + '.');
        } else {
            errEl.textContent = (result && result.message) || 'Submission failed. Please try again.';
            errEl.style.display = 'block';
            btn.disabled = false;
            btn.textContent = 'Submit Request';
        }
    }

    // ── Privacy Consent Artifact (PCA) & QR ────────────────────────────
    function generatePCAArtifact() {
        const latest = historyCache.length > 0 ? historyCache[0] : null;
        const slimConsents = latest
            ? (latest.data_point_consents || []).map(c => ({ id: c.data_point_id, g: c.consent_granted }))
            : [];
        // The persona-matched policy (already selected in the Manage Consent tab), independent of
        // whether any consent has been saved yet -- lets the wallet show org/persona and offer
        // first-time consent even before a consent record exists.
        const policyEntry = activePolicyEntry || (SESSION && SESSION.policies ? SESSION.policies[0] : null);
        return {
            v: "1.0",
            uid: SESSION ? SESSION.userId : null,
            fid: SESSION ? SESSION.fiduciaryId : null,
            sync_url: PORTAL_BASE_URL + '/api/v1/client/wallet',
            // Issued at login, independent of consent history -- so the PCA is valid even before
            // the principal has saved any preferences (the wallet syncs fresh details afterward).
            sync_token: SESSION ? SESSION.syncToken : null,
            consents: slimConsents,
            policy_id: policyEntry ? policyEntry.policy_id : null,
            policy_version: policyEntry ? (policyEntry.version || '') : '',
            policy_ref: latest ? `${latest.policy_id}-v${latest.policy_version}` : (policyEntry ? `${policyEntry.policy_id}-v${policyEntry.version || ''}` : 'N/A'),
            generated_at: new Date().toISOString()
        };
    }

    function updateQR() {
        if (typeof QRCode === 'undefined') return;
        const container = document.getElementById('qrcode-container');
        if (!container) return;
        try {
            container.innerHTML = '';
            const correctLevel = (QRCode.CorrectLevel && QRCode.CorrectLevel.M != null)
                ? QRCode.CorrectLevel.M
                : 0;
            new QRCode(container, {
                text: JSON.stringify(generatePCAArtifact()),
                width: 80,
                height: 80,
                colorDark: '#006A67',
                colorLight: '#ffffff',
                correctLevel: correctLevel
            });
        } catch (e) {
            console.warn('QR generation skipped:', e.message);
        }
    }

    function downloadPCA() {
        const artifact = generatePCAArtifact();
        const blob = new Blob([JSON.stringify(artifact, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `TSI_Consent_Artifact_${artifact.uid || 'export'}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function togglePcaPopover() {
        const pop = document.getElementById('pca-popover');
        pop.style.display = pop.style.display === 'flex' ? 'none' : 'flex';
    }

    // Close the PCA popover when clicking outside it
    document.addEventListener('click', (e) => {
        const wrap = document.getElementById('pca-toggle-wrap');
        const pop = document.getElementById('pca-popover');
        if (pop.style.display === 'flex' && !wrap.contains(e.target)) {
            pop.style.display = 'none';
        }
    });

    // ── Bootstrap ───────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        SESSION = requireAuth();
        if (!SESSION) return;

        document.getElementById('header-fiduciary').textContent = SESSION.fiduciaryName;
        document.getElementById('header-user').textContent = 'Logged in as: ' + SESSION.userId;

        // Populate session strip
        document.getElementById('pca-user-id').textContent = SESSION.userId;
        document.getElementById('pca-fiduciary').textContent = SESSION.fiduciaryName;

        const pcaEnabled = SESSION.pcaQrEnabled !== false;
        if (pcaEnabled) {
            document.getElementById('pca-toggle-wrap').style.display = 'block';
        }

        // Fetch the latest consent record in the background to get a valid sync_token
        // before the user visits the History tab, so the downloaded PCA is always complete.
        apiCall('/api/v1/client/consent', 'list_consent_history', {
            user_id: SESSION.userId,
            fiduciary_id: SESSION.fiduciaryId,
            limit: 1
        }).then(result => {
            const records = Array.isArray(result) ? result : (result && result.data ? result.data : []);
            if (records.length > 0 && historyCache.length === 0) historyCache = records;
            if (pcaEnabled) setTimeout(updateQR, 0);
        });

        setTab('consent');
    });

    // Close detail modal on backdrop click
    document.getElementById('detail-modal').addEventListener('click', function(e) {
        if (e.target === this) this.style.display = 'none';
    });

    // Withdraw modal: close on backdrop click, close button, and cancel button
    const _wModal = document.getElementById('withdraw-modal');
    _wModal.addEventListener('click', function(e) {
        if (e.target === this) this.style.display = 'none';
    });
    document.getElementById('withdraw-modal-close').addEventListener('click', () => {
        _wModal.style.display = 'none';
    });
    document.getElementById('withdraw-cancel-btn').addEventListener('click', () => {
        _wModal.style.display = 'none';
    });
    document.getElementById('withdraw-submit-btn').addEventListener('click', async () => {
        const selected = Array.from(_wModal.querySelectorAll('.withdraw-purpose-chk:checked')).map(el => el.value);
        if (selected.length === 0) {
            alert('Please select at least one purpose to withdraw.');
            return;
        }
        _wModal.style.display = 'none';
        await withdrawConsent(_wModal.dataset.policyId, selected);
    });
