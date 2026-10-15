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
    const API_URL_POLICY = '/api/v1/policy';
    const PAGE_SIZE = 25;
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    if (localStorage.getItem('role') === 'OPERATOR') {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
    }
    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'DPO User';

    // --- Global DOM Element Variables ---
    let sidebar, menuToggle, backdrop;
    let filterForm, filterUser, filterPolicy, filterStatus, filterStart, filterEnd, filterActive, resetBtn;
    let consentsBody, resultCount, prevBtn, nextBtn, pageLabel;
    let consentDetailModalOverlay, closeDetailModalBtn;
    let modalRecordId, modalRecordStatus, granularConsentDetails, provenanceDetails;

    let currentPage = 1;
    let totalRecords = 0;

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

    async function apiPost(url, payload) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
            body: JSON.stringify(Object.assign({ fiduciary_id: FIDUCIARY_ID }, payload))
        });
        const body = await response.json();
        if (response.status === 401) {
            alert("Session Expired: " + (body.message || "Authentication required."));
            handleLogout();
            throw new Error('unauthorized');
        }
        if (!response.ok) throw new Error(body.message || `API returned status ${response.status}`);
        return body;
    }

    function createStatusBadge(status, isActive) {
        let colorClass = 'bg-gray-100 text-gray-800';
        const s = (status || '').toUpperCase();

        if (isActive === true) {
            colorClass = 'bg-green-100 text-green-700 border border-green-200';
            if (s === 'DENIED_ALL' || s === 'WITHDRAWN' || s === 'ERASURE_REQUESTED' || s === 'CONSENT_WITHDRAWN') {
                colorClass = 'bg-red-100 text-red-700 border border-red-200';
            }
        } else if (isActive === false) {
            colorClass = 'bg-gray-200 text-gray-600'; // Archived/Inactive
        }
        return `<span class="px-3 py-1 text-xs font-bold rounded-full uppercase ${colorClass}">${esc(s.replace(/_/g, ' '))}</span>`;
    }

    function createConsentRow(record) {
        const row = document.createElement('tr');
        row.className = 'clickable-row';
        const versionLabel = record.policy_version ? ` (v${esc(record.policy_version)})` : '';
        row.innerHTML = `
            <td class="px-4 py-3 text-sm font-mono text-gray-700">${esc(record.user_id)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(record.policy_id)}${versionLabel}</td>
            <td class="px-4 py-3 text-sm">${createStatusBadge(record.consent_status_general, record.is_active_consent)}</td>
            <td class="px-4 py-3 text-sm font-bold text-slate-500">${record.is_active_consent ? 'Yes' : 'No'}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(record.purposes_granted)} / ${esc(record.purposes_total)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(new Date(record.timestamp).toLocaleString())}</td>
            <td class="px-4 py-3 text-sm">
                <button class="view-record-btn text-indigo-600 hover:text-indigo-900 font-bold text-sm">View Details</button>
            </td>
        `;
        const open = () => viewConsentRecord(record.user_id, record.record_id);
        row.querySelector('.view-record-btn').addEventListener('click', (e) => { e.stopPropagation(); open(); });
        row.addEventListener('click', open);
        return row;
    }

    // --- Core Logic ---

    function currentFilters() {
        const payload = { "_func": "list_consents", "page": currentPage, "limit": PAGE_SIZE };
        if (filterUser.value.trim()) payload.user_id = filterUser.value.trim();
        if (filterPolicy.value) payload.policy_id = filterPolicy.value;
        if (filterStatus.value) payload.status = filterStatus.value;
        if (filterActive.checked) payload.active_only = true;
        if (filterStart.value) payload.start_date = filterStart.value;
        // Include the whole end day rather than stopping at midnight.
        if (filterEnd.value) payload.end_date = filterEnd.value + 'T23:59:59';
        return payload;
    }

    async function loadConsents() {
        consentsBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">Loading consent records...</td></tr>`;
        try {
            const responseData = await apiPost(API_URL_CONSENT, currentFilters());
            const records = responseData.data || [];
            totalRecords = responseData.total || 0;

            consentsBody.innerHTML = '';
            if (records.length === 0) {
                consentsBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">No consent records match these filters.</td></tr>`;
            } else {
                records.forEach(record => consentsBody.appendChild(createConsentRow(record)));
            }
            resultCount.textContent = `${totalRecords} Total`;
            updatePager();
        } catch (error) {
            if (error.message === 'unauthorized') return;
            consentsBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-red-600">Error loading consent records: ${esc(error.message)}</td></tr>`;
        }
    }

    function updatePager() {
        const lastPage = Math.max(1, Math.ceil(totalRecords / PAGE_SIZE));
        pageLabel.textContent = `Page ${currentPage} of ${lastPage}`;
        prevBtn.disabled = currentPage <= 1;
        nextBtn.disabled = currentPage >= lastPage;
    }

    async function loadPolicyFilter() {
        try {
            // list_policies validates on search/status/fiduciary_id_filter being present, even when blank.
            const policies = await apiPost(API_URL_POLICY, {
                "_func": "list_policies",
                "search": "",
                "status": "",
                "fiduciary_id_filter": FIDUCIARY_ID,
                "limit": 100
            });
            const rows = Array.isArray(policies) ? policies : (policies.data || []);
            rows.forEach(p => {
                const option = document.createElement('option');
                option.value = p.id || p.policy_id;
                option.textContent = p.version ? `${option.value} (v${p.version})` : option.value;
                filterPolicy.appendChild(option);
            });
        } catch (error) {
            // A missing policy list only costs us the dropdown; the table still loads.
            console.error('Could not load policies for filter:', error);
        }
    }

    async function viewConsentRecord(userId, recordId) {
        showModal();
        modalRecordId.textContent = userId;
        modalRecordStatus.innerHTML = '';
        provenanceDetails.innerHTML = '';
        granularConsentDetails.innerHTML = `<p class="text-gray-500">Fetching record ${esc(recordId)}...</p>`;

        try {
            const record = await apiPost(API_URL_CONSENT, { "_func": "get_consent_record_details", "record_id": recordId });

            modalRecordStatus.innerHTML = createStatusBadge(record.consent_status_general, record.is_active_consent);
            provenanceDetails.innerHTML = `
                <p><strong>Record ID:</strong> ${esc(record.id)}</p>
                <p><strong>Policy Ref:</strong> ${esc(record.policy_id)} (v${esc(record.policy_version || '—')})</p>
                <p><strong>Time:</strong> ${esc(new Date(record.timestamp).toLocaleString())} (${esc(record.consent_mechanism)})</p>
                <p><strong>Jurisdiction:</strong> ${esc(record.jurisdiction || 'N/A')} | <strong>Language:</strong> ${esc(record.language_selected || 'N/A')}</p>
                <p><strong>IP:</strong> ${esc(record.ip_address || 'N/A')} | <strong>User Agent:</strong> ${esc(record.user_agent || 'N/A')}</p>
            `;

            const preferences = record.data_point_consents || [];
            let detailsHtml = '';
            preferences.forEach(pref => {
                const label = pref.purpose_agreed_to || pref.data_point_id || 'Purpose';
                const statusBadge = pref.consent_granted === true
                    ? `<span class="text-green-600 font-bold">GRANTED</span>`
                    : `<span class="text-red-600 font-bold">DENIED</span>`;
                detailsHtml += `
                    <div class="policy-detail-item">
                        <p class="text-gray-800 font-medium">${esc(label)}:</p>
                        <p class="ml-4">${statusBadge}${pref.timestamp_updated ? ` <span class="text-gray-400 text-xs">${esc(new Date(pref.timestamp_updated).toLocaleString())}</span>` : ''}</p>
                    </div>
                `;
            });
            granularConsentDetails.innerHTML = detailsHtml || '<p class="text-gray-500">No granular purposes recorded.</p>';
        } catch (error) {
            if (error.message === 'unauthorized') return;
            granularConsentDetails.innerHTML = `<p class="text-red-600">Error fetching details: ${esc(error.message)}</p>`;
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
        filterForm = document.getElementById('filter-form');
        filterUser = document.getElementById('filter-user');
        filterPolicy = document.getElementById('filter-policy');
        filterStatus = document.getElementById('filter-status');
        filterStart = document.getElementById('filter-start');
        filterEnd = document.getElementById('filter-end');
        filterActive = document.getElementById('filter-active');
        resetBtn = document.getElementById('reset-btn');
        consentsBody = document.getElementById('consents-body');
        resultCount = document.getElementById('result-count');
        prevBtn = document.getElementById('prev-btn');
        nextBtn = document.getElementById('next-btn');
        pageLabel = document.getElementById('page-label');
        consentDetailModalOverlay = document.getElementById('consent-detail-modal-overlay');
        closeDetailModalBtn = document.getElementById('close-detail-modal-btn');
        modalRecordId = document.getElementById('modal-record-id');
        modalRecordStatus = document.getElementById('modal-record-status');
        granularConsentDetails = document.getElementById('granular-consent-details');
        provenanceDetails = document.getElementById('provenance-details');

        menuToggle.addEventListener('click', toggleMenu);
        backdrop.addEventListener('click', toggleMenu);
        closeDetailModalBtn.addEventListener('click', closeModal);
        consentDetailModalOverlay.addEventListener('click', (event) => {
            if (event.target === consentDetailModalOverlay) closeModal();
        });

        filterForm.addEventListener('submit', (event) => {
            event.preventDefault();
            currentPage = 1;
            loadConsents();
        });

        resetBtn.addEventListener('click', () => {
            filterForm.reset();
            currentPage = 1;
            loadConsents();
        });

        prevBtn.addEventListener('click', () => {
            if (currentPage > 1) { currentPage -= 1; loadConsents(); }
        });

        nextBtn.addEventListener('click', () => {
            if (currentPage < Math.ceil(totalRecords / PAGE_SIZE)) { currentPage += 1; loadConsents(); }
        });

        loadPolicyFilter();
        loadConsents();
    });

    window.viewConsentRecord = viewConsentRecord;
    window.toggleMenu = toggleMenu;
