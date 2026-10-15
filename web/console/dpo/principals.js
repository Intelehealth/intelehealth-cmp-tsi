// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        print: () => window.print(),
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
    const API_URL_CONSENT = '/api/v1/consent';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    if (localStorage.getItem('role') === 'OPERATOR') {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
    }
    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'DPO User';

    // --- Global DOM Element Variables ---
    let sidebar, menuToggle, backdrop;
    let principalSearchForm, principalIdInput, searchMessage;
    let consentHistoryCard, principalDisplayId, consentTableBody, consentDetailModalOverlay, closeDetailModalBtn;
    let modalRecordId, modalRecordStatus, granularConsentDetails, provenanceDetails;
    let principalStatusCard, overallStatusBadge, mainInitiateErasureBtn;
    let recentPrincipalsCard, recentPrincipalsBody;

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

    function createHistoryRow(record, userId) {
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
                <button data-uid="${esc(userId)}" data-rid="${esc(record.id)}" class="view-record-btn text-indigo-600 hover:text-indigo-900 font-bold text-sm">View Details</button>
            </td>
        `;
        const btn = row.querySelector('.view-record-btn');
        btn.addEventListener('click', () => viewConsentRecord(btn.dataset.uid, btn.dataset.rid));
        return row;
    }

    // --- Core Logic ---

    function createRecentPrincipalRow(principal) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="px-4 py-3 text-sm font-mono text-gray-700">${esc(principal.user_id)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(principal.last_consent_mechanism || 'N/A')}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(principal.age_category || 'N/A')}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(principal.verification_status || 'N/A')}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(new Date(principal.created_at).toLocaleDateString())}</td>
            <td class="px-4 py-3 text-sm">
                <button class="view-recent-principal-btn text-indigo-600 hover:text-indigo-900 font-bold text-sm">View</button>
            </td>
        `;
        const btn = row.querySelector('.view-recent-principal-btn');
        btn.addEventListener('click', () => {
            principalIdInput.value = principal.user_id;
            loadConsentHistory(principal.user_id);
        });
        return row;
    }

    async function loadRecentPrincipals() {
        try {
            const response = await fetch(API_URL_CONSENT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_principals", "fiduciary_id": localStorage.getItem("fiduciary_id"), "limit": 20 })
            });
            const principals = await response.json();

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

    async function loadConsentHistory(principalIdentifier) {
        recentPrincipalsCard.classList.add('hidden');
        consentHistoryCard.classList.add('hidden');
        principalStatusCard.classList.add('hidden');
        consentTableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">Searching...</td></tr>`;
        searchMessage.classList.add('hidden');

        try {
            const payload = {
                "_func": "list_consent_history",
                "user_id": principalIdentifier,
                "fiduciary_id": localStorage.getItem("fiduciary_id")
            };

            const response = await fetch(API_URL_CONSENT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            const responseData = await response.json();

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
                    mainInitiateErasureBtn.onclick = () => initiateErasurePurge(principalIdentifier);
                } else {
                    mainInitiateErasureBtn.classList.add('hidden');
                }

                principalStatusCard.classList.remove('hidden');
                records.forEach(record => {
                    consentTableBody.appendChild(createHistoryRow(record, principalIdentifier));
                });
                principalDisplayId.textContent = principalIdentifier;
                consentHistoryCard.classList.remove('hidden');
            } else {
                consentTableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">No records found.</td></tr>`;
                recentPrincipalsCard.classList.remove('hidden');
            }
        } catch (error) {
            consentTableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-red-600">Error loading data.</td></tr>`;
        }
    }

    async function viewConsentRecord(userId, recordId) {
        showModal();
        granularConsentDetails.innerHTML = `<p class="text-gray-500">Fetching record ${esc(recordId)}...</p>`;

        try {
            const payload = {
                "_func": "get_consent_record_details",
                "record_id": recordId,
                "fiduciary_id": localStorage.getItem("fiduciary_id")
            };

            const response = await fetch(API_URL_CONSENT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            const record = await response.json();

            if (response.ok && record) {
                modalRecordId.textContent = userId;
                modalRecordStatus.innerHTML = createStatusBadge(record.consent_status_general, record.is_active_consent);

                provenanceDetails.innerHTML = `
                    <p><strong>Policy Ref:</strong> ${esc(record.policy_id)} (v${esc(record.policy_version || '—')})</p>
                    ${record.ropa_entry_id ? `<p><strong>ROPA Entry:</strong> ${esc(record.ropa_activity_name || record.ropa_entry_id)}</p>` : ''}
                    <p><strong>Time:</strong> ${esc(new Date(record.timestamp).toLocaleString())} (${esc(record.consent_mechanism)})</p>
                    <p><strong>IP:</strong> ${esc(record.ip_address || 'N/A')} | <strong>User Agent:</strong> ${esc(record.user_agent || 'N/A')}</p>
                `;

                let detailsHtml = '';
                const preferences = record.data_point_consents;

                for (const purposeId in preferences) {
                    const purpose = preferences[purposeId].purpose_agreed_to;
                    const status = preferences[purposeId].consent_granted;
                    const statusBadge = status === true
                        ? `<span class="text-green-600 font-bold">GRANTED</span>`
                        : `<span class="text-red-600 font-bold">DENIED</span>`;

                    detailsHtml += `
                        <div class="policy-detail-item">
                            <p class="text-gray-800 font-medium">${esc(purpose)}:</p>
                            <p class="ml-4">${statusBadge}</p>
                        </div>
                    `;
                }
                granularConsentDetails.innerHTML = detailsHtml || '<p class="text-gray-500">No granular purposes recorded.</p>';
            }
        } catch (error) {
            granularConsentDetails.innerHTML = `<p class="text-red-600">Error fetching details.</p>`;
        }
    }

    async function initiateErasurePurge(userId) {
        if (confirm(`Confirm: Initiate full Data Erasure/Purge workflow for Data Principal ID ${userId}?`)) {
            try {
                const response = await fetch(API_URL_CONSENT, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({
                        "_func": "erasure_request",
                        "user_id": userId,
                        "language_selected": "en",
                        "reason": "DPO initiated erasure.",
                        "fiduciary_id": localStorage.getItem("fiduciary_id")
                    })
                });
                if (response.ok) {
                    alert("Erasure request submitted.");
                    loadConsentHistory(userId);
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

        menuToggle.addEventListener('click', toggleMenu);
        backdrop.addEventListener('click', toggleMenu);
        closeDetailModalBtn.addEventListener('click', closeModal);

        principalSearchForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const identifier = principalIdInput.value.trim();
            if (identifier) loadConsentHistory(identifier);
        });

        loadRecentPrincipals();
    });

    window.viewConsentRecord = viewConsentRecord;
    window.toggleMenu = toggleMenu;
