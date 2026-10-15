// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        toggleSidebar: () => toggleSidebar(),
        handleLogout: () => handleLogout(),
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
    const changeHandlers = {
        loadDpoMetrics: () => loadDpoMetrics(),
    };
    document.querySelectorAll('[data-change-action]').forEach((el) => {
        const fn = changeHandlers[el.getAttribute('data-change-action')];
        if (fn) el.addEventListener('change', (e) => fn(el, e));
    });
})();

    const API_URL_DASHBOARD = '/api/v1/admin/admindash';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    // Operators are restricted from policy authoring and system settings.
    if (localStorage.getItem('role') === 'OPERATOR') {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
    }

    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('backdrop').classList.toggle('active');
    }

    /**
     * Initializes the Month Filter dropdown for current + 3 previous months.
     */
    function setupFilter() {
        const filter = document.getElementById('time-filter');
        const options = [];
        const now = new Date();

        for (let i = 0; i < 4; i++) {
            const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const label = i === 0 ? "Current Month" : d.toLocaleString('default', { month: 'long', year: 'numeric' });

            // Format first and last day strings (YYYY-MM-DD)
            const firstDay = new Date(d.getFullYear(), d.getMonth(), 1).toISOString().split('T')[0];
            const lastDay = new Date(d.getFullYear(), d.getMonth() + 1, 0).toISOString().split('T')[0];

            options.push(`<option value="${firstDay}|${lastDay}">${label}</option>`);
        }
        filter.innerHTML = options.join('');
    }

    /**
     * Fetches and renders the simplified metrics based on the selected time period.
     */
    async function loadDpoMetrics() {
        const filterEl = document.getElementById('time-filter');
        if (!filterEl.value) return;

        const [start, end] = filterEl.value.split('|');

        try {
            const response = await fetch(API_URL_DASHBOARD, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({
                    "_func": "get_dpo_metrics",
                    "fiduciary_id": FIDUCIARY_ID,
                    "start_date": start,
                    "end_date": end
                })
            });

            const data = await response.json();

            if (data.status === 401) {
                alert("Session Expired: " + (data.message || "Authentication required."));
                handleLogout();
                return;
            }

            if (data.success && data.metrics) {
                const m = data.metrics;
                document.getElementById('metric-active-policies').textContent = m.active_policies || 0;
                document.getElementById('metric-consents').textContent = m.total_consents || 0;
                document.getElementById('metric-principals').textContent = m.data_principals || 0;

                // Consolidated Purge Card
                document.getElementById('metric-purge-total').textContent = m.purge_total || 0;
                document.getElementById('metric-purge-pending').textContent = `(${m.purge_pending || 0} Pending)`;

                // Consolidated Grievance Card
                document.getElementById('metric-grievances-total').textContent = m.grievances_total || 0;
                document.getElementById('metric-grievances-pending').textContent = `(${m.grievances_pending || 0} Pending)`;
            }
        } catch (error) {
            console.error("Metric load failure:", error);
            document.querySelectorAll('[id^="metric-"]').forEach(el => el.textContent = 'Err');
        }
    }

    /**
     * Fetches the urgent pending grievances for the table view.
     */
    async function loadPendingGrievances() {
        const tbody = document.getElementById('grievance-table-body');
        try {
            const response = await fetch(API_URL_DASHBOARD, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_pending_grievances", "fiduciary_id": FIDUCIARY_ID, "limit": 10 })
            });

            const grievances = await response.json();
            if (Array.isArray(grievances)) {
                if (grievances.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="p-8 text-center text-slate-400 italic">No urgent tasks requiring action.</td></tr>';
                    return;
                }

                tbody.innerHTML = grievances.map(g => {
                    const isOverdue = g.days_left < 0;
                    return `
                        <tr class="hover:bg-slate-50 transition-colors">
                            <td class="px-4 py-3 font-mono text-xs text-slate-500">...${esc(String(g.grievance_id || '').slice(-8))}</td>
                            <td class="px-4 py-3 font-bold text-slate-700">${esc(String(g.type || '').replace(/_/g, ' '))}</td>
                            <td class="px-4 py-3 text-slate-500">${esc(new Date(g.submission_timestamp).toLocaleDateString())}</td>
                            <td class="px-4 py-3 font-semibold ${isOverdue ? 'text-red-600' : 'text-slate-600'}">
                                ${esc(isOverdue ? Math.abs(g.days_left) + ' days OVERDUE' : g.days_left + ' days left')}
                            </td>
                            <td class="px-4 py-3">
                                <span class="px-2 py-0.5 rounded-full text-[10px] font-black uppercase bg-blue-100 text-blue-700">${esc(g.status)}</span>
                            </td>
                        </tr>
                    `;
                }).join('');
            }
        } catch (error) {
            tbody.innerHTML = '<tr><td colspan="5" class="p-8 text-center text-red-500">Failed to sync with registry.</td></tr>';
        }
    }

    function handleLogout() {
        localStorage.clear();
        window.location.href = "../index.html";
    }

    window.onload = () => {
        setupFilter();
        loadDpoMetrics();
        loadPendingGrievances();

        if (FIDUCIARY_ID) document.getElementById('fiduciary-id-display').textContent = FIDUCIARY_ID;

        const storedUser = localStorage.getItem('username');
        if (storedUser) document.getElementById('username').textContent = storedUser;
    };
