// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        toggleSidebar: () => toggleSidebar(),
        handleLogout: () => handleLogout(),
        exportRopa: () => exportRopa(),
        exportRopaPdf: () => exportRopaPdf(),
        closeViewModal: () => closeViewModal(),
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
    const changeHandlers = {
        loadEntries: () => loadEntries(),
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

    const API = '/api/v1/admin/ropa';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    if (localStorage.getItem('role') === 'OPERATOR') {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
    }

    const REQUIRED_FIELDS = [
        'activity_name','purpose','legal_basis','data_categories','data_subject_categories',
        'retention_period_days','retention_start_event','dpo_id','security_measures'
    ];

    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('backdrop').classList.toggle('active');
    }

    function handleLogout() { localStorage.clear(); window.location.href = '../index.html'; }

    // ---- Status badges ----
    function statusBadge(status) {
        const map = {
            draft:        'bg-yellow-100 text-yellow-800',
            active:       'bg-green-100 text-green-800',
            under_review: 'bg-blue-100 text-blue-800',
            retired:      'bg-gray-100 text-gray-600'
        };
        return `<span class="px-2 py-0.5 text-[10px] font-black rounded-full uppercase ${map[status] || 'bg-red-50 text-red-700'}">${esc(status)}</span>`;
    }

    // ---- Load entries ----
    const POLICY_FILTER = new URLSearchParams(window.location.search).get('policy');

    async function loadEntries() {
        const tbody = document.getElementById('ropa-table-body');
        tbody.innerHTML = '<tr><td colspan="7" class="p-6 text-center text-gray-400 italic">Syncing with registry...</td></tr>';
        const status = document.getElementById('status-filter').value;
        const basis  = document.getElementById('basis-filter').value;

        try {
            const res = await fetch(API, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ _func: 'list_entries', fiduciary_id: FIDUCIARY_ID, status, legal_basis: basis, limit: 50 })
            });
            if (res.status === 401) { handleLogout(); return; }
            const data = await res.json();
            let entries = Array.isArray(data) ? data : (data.data || []);
            if (POLICY_FILTER) {
                entries = entries.filter(e => parseArr(e.linked_policy_ids).includes(POLICY_FILTER));
            }
            if (!entries.length) {
                tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-slate-400 italic">${POLICY_FILTER ? `No ROPA entries found for policy ${esc(POLICY_FILTER)}.` : 'No ROPA entries found. When a policy admin publishes a policy, entries will appear here for your review.'}</td></tr>`;
                return;
            }
            tbody.innerHTML = '';
            renderGrouped(entries, tbody);
        } catch(err) {
            tbody.innerHTML = `<tr><td colspan="7" class="p-6 text-center text-red-500 font-bold">API connection error.</td></tr>`;
        }
    }

    function renderGrouped(entries, tbody) {
        const groups = {};
        entries.forEach(e => {
            const key = parseArr(e.linked_policy_ids)[0] || '__none__';
            if (!groups[key]) groups[key] = [];
            groups[key].push(e);
        });

        // Preserve entry arrival order (SQL returns created_at DESC) so most-recent group appears first
        const keys = [];
        const seen = new Set();
        entries.forEach(e => {
            const key = parseArr(e.linked_policy_ids)[0] || '__none__';
            if (key !== '__none__' && !seen.has(key)) { keys.push(key); seen.add(key); }
        });
        if (groups['__none__']) keys.push('__none__');

        keys.forEach(key => {
            const group = groups[key];
            const label = key === '__none__' ? 'Other Processing Activities' : key;
            const n = group.length;

            const hdr = document.createElement('tr');
            hdr.className = 'bg-teal-50 border-t-2 border-teal-200';
            hdr.innerHTML = `
                <td colspan="7" class="px-4 py-2">
                    <span class="text-[10px] font-black text-teal-600 uppercase tracking-widest">Policy</span>
                    <span class="font-mono font-bold text-teal-800 ml-2">${esc(label)}</span>
                    <span class="text-xs text-teal-400 ml-3">${n} activit${n === 1 ? 'y' : 'ies'}</span>
                </td>
            `;
            tbody.appendChild(hdr);
            group.forEach(e => tbody.appendChild(buildRow(e)));
        });
    }

    function buildRow(e) {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-50/50 transition-colors';

        const retention = e.retention_period_days
            ? `${esc(e.retention_period_days)}d (${esc(e.retention_start_event || '—')})`
            : '<span class="text-red-400 text-[10px] font-bold">NOT SET</span>';
        const policy = parseArr(e.linked_policy_ids)[0] || '—';

        const actions = `
            <button class="view-entry-btn text-teal-700 hover:text-teal-900 font-bold text-xs mr-2" data-entry-id="${esc(e.id)}">View</button>
        `;

        tr.innerHTML = `
            <td class="px-4 py-4 text-sm font-bold text-slate-800 max-w-[240px]">
                <div class="truncate" title="${esc(e.activity_name)}">${esc(e.activity_name)}</div>
                <div class="text-[10px] font-mono text-slate-400 mt-0.5">${esc(String(e.id).slice(0,8))}…</div>
            </td>
            <td class="px-4 py-4 text-xs font-mono text-indigo-600 whitespace-nowrap">${esc(policy)}</td>
            <td class="px-4 py-4 text-xs text-slate-500 whitespace-nowrap capitalize">${esc((e.legal_basis||'').replace(/_/g,' '))}</td>
            <td class="px-4 py-4 whitespace-nowrap">${statusBadge(e.status)}</td>
            <td class="px-4 py-4 text-xs text-slate-500 whitespace-nowrap">${retention}</td>
            <td class="px-4 py-4 text-xs text-slate-500 text-center">v${esc(e.version)}</td>
            <td class="px-4 py-4 whitespace-nowrap">${actions}</td>
        `;
        tr.querySelector('.view-entry-btn').addEventListener('click', () => viewEntry(e.id));
        return tr;
    }

    function parseArr(val) {
        if (!val) return [];
        if (Array.isArray(val)) return val;
        try { return JSON.parse(val); } catch(e) { return []; }
    }

    // ---- View / Completeness ----
    async function viewEntry(id) {
        document.getElementById('view-modal').style.display = 'flex';
        document.getElementById('v-history').innerHTML = '<p class="text-xs text-slate-400 italic">Loading...</p>';
        document.getElementById('v-checklist').innerHTML = '<p class="text-xs text-slate-400 italic">Loading...</p>';

        try {
            const [entryRes, validateRes] = await Promise.all([
                fetch(API, { method:'POST', headers:{ 'Content-Type':'application/json','Authorization':`Bearer ${AUTH_TOKEN}` }, body: JSON.stringify({ _func:'get_entry', id }) }),
                fetch(API, { method:'POST', headers:{ 'Content-Type':'application/json','Authorization':`Bearer ${AUTH_TOKEN}` }, body: JSON.stringify({ _func:'validate_completeness', id }) })
            ]);

            const e = await entryRes.json();
            const v = await validateRes.json();

            document.getElementById('view-modal-title').textContent   = e.activity_name || 'Entry';
            document.getElementById('view-modal-subtitle').textContent = `ID: ${e.id} • Status: ${e.status} • v${e.version}`;
            document.getElementById('v-legal-basis').textContent   = (e.legal_basis || '—').replace(/_/g,' ');
            document.getElementById('v-purpose').textContent        = e.purpose || '—';
            document.getElementById('v-retention').textContent      = e.retention_period_days ? `${e.retention_period_days} days (${e.retention_start_event || '—'})` : '—';
            document.getElementById('v-security').textContent       = e.security_measures || '—';
            document.getElementById('v-data-categories').textContent = prettyJson(e.data_categories);
            document.getElementById('v-data-subjects').textContent  = prettyJson(e.data_subject_categories);
            document.getElementById('v-processors').textContent     = prettyJson(e.processors);
            document.getElementById('v-cross-border').textContent   = prettyJson(e.cross_border_transfers);
            document.getElementById('v-linked-policies').textContent = prettyJson(e.linked_policy_ids);
            document.getElementById('v-dpo-id').textContent         = e.dpo_id || '—';
            document.getElementById('v-consent-count').textContent         = e.consent_count !== undefined && e.consent_count !== null ? e.consent_count.toString() : '0';
            document.getElementById('v-inactive-consent-count').textContent = e.inactive_consent_count !== undefined && e.inactive_consent_count !== null ? e.inactive_consent_count.toString() : '0';

            // History
            const histEl = document.getElementById('v-history');
            if (e.history && e.history.length) {
                histEl.innerHTML = e.history.map(h => `
                    <div class="history-row">
                        <div class="flex justify-between items-center">
                            <span class="text-xs font-bold text-slate-600">Version ${esc(h.version)}</span>
                            <span class="text-[10px] text-slate-400">${esc(new Date(h.changed_at).toLocaleString())}</span>
                        </div>
                        ${h.changed_by ? `<div class="text-[10px] text-slate-400 font-mono mt-0.5">by ${esc(String(h.changed_by).slice(0,8))}…</div>` : ''}
                    </div>
                `).join('');
            } else {
                histEl.innerHTML = '<p class="text-xs text-slate-400 italic">No history recorded.</p>';
            }

            // Completeness checklist
            renderChecklist(v);

        } catch(err) {
            document.getElementById('v-checklist').innerHTML = '<p class="text-xs text-red-500">Failed to load.</p>';
        }
    }

    function renderChecklist(v) {
        const checkEl = document.getElementById('v-checklist');
        const banner  = document.getElementById('v-completeness-banner');
        // dpo_id is excluded — it is auto-set from the logged-in user's session at publish time
        const allFields = [
            'activity_name','purpose','legal_basis','data_categories','data_subject_categories',
            'retention_period_days','retention_start_event','security_measures','cross_border_transfers'
        ];
        const missingArr = Array.isArray(v.missing_fields) ? v.missing_fields.map(f => f.split(' ')[0]) : [];
        const missing = new Set(missingArr);

        checkEl.innerHTML = allFields.map(f => {
            const ok = !Array.from(missing).some(m => m.startsWith(f));
            const label = f.replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase());
            return `<div class="checklist-item ${ok ? 'checklist-ok' : 'checklist-fail'}">
                <span>${ok ? '✓' : '✗'}</span>
                <span>${esc(label)}</span>
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

    function closeViewModal() {
        document.getElementById('view-modal').style.display = 'none';
    }

    // ---- Retire ----
    async function retireEntry(id, name) {
        if (!confirm(`Retire "${name}"?\n\nThis entry will be marked as retired. This cannot be undone.`)) return;
        const res = await fetch(API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
            body: JSON.stringify({ _func: 'retire_entry', id })
        });
        const data = await res.json();
        if (res.ok && data.success) loadEntries();
        else alert(data.message || 'Retire failed.');
    }

    // ---- Export ----
    async function exportRopa() {
        const res = await fetch(API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
            body: JSON.stringify({ _func: 'export_ropa', fiduciary_id: FIDUCIARY_ID })
        });
        if (!res.ok) { alert('Export failed.'); return; }
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'ropa_export.csv'; a.click();
        URL.revokeObjectURL(url);
    }

    async function exportRopaPdf() {
        let entries;
        try {
            const res = await fetch(API, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ _func: 'list_entries', fiduciary_id: FIDUCIARY_ID, status: 'active', limit: 200 })
            });
            const data = await res.json();
            entries = Array.isArray(data) ? data : (data.data || []);
        } catch(e) { alert('Failed to fetch entries for HTML export.'); return; }

        if (!entries.length) { alert('No active ROPA entries to export.'); return; }

        const generated = new Date().toLocaleString('en-IN', { dateStyle:'long', timeStyle:'short' });
        function lsVal(k) { const v = localStorage.getItem(k); return (v && v !== 'undefined' && v !== 'null') ? v : null; }
        const fiduciary = lsVal('fiduciary_name') || lsVal('username') || FIDUCIARY_ID || 'Organisation';

        const css = `
            *, *::before, *::after { box-sizing: border-box; }
            body { font-family: ui-sans-serif, system-ui, sans-serif; max-width: 1000px; margin: 0 auto; padding: 32px 24px; color: #1e293b; background: #f8fafc; }
            .page-hdr { background: #006A67; color: white; padding: 28px 36px; border-radius: 12px 12px 0 0; }
            .page-hdr-label { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em; opacity: 0.75; margin-bottom: 6px; }
            .page-hdr h1 { margin: 0 0 4px; font-size: 1.5rem; font-weight: 800; }
            .page-hdr p { margin: 0; font-size: 0.82rem; opacity: 0.85; }
            .register { background: white; border-radius: 0 0 12px 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; margin-bottom: 32px; }
            .entry { border-bottom: 2px solid #f1f5f9; padding: 28px 36px; }
            .entry:last-child { border-bottom: none; }
            .entry-hdr { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
            .entry-title { font-size: 1rem; font-weight: 800; color: #006A67; font-family: monospace; }
            .badge { display: inline-block; font-size: 0.65rem; font-weight: 800; padding: 3px 10px; border-radius: 4px; }
            .badge-active { background: #dcfce7; color: #166534; }
            .badge-consent { background: #e0f2f1; color: #006A67; }
            .section-title { font-size: 0.62rem; font-weight: 800; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; border-bottom: 1px solid #f1f5f9; padding-bottom: 5px; margin: 18px 0 10px; }
            .field-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
            .field-label { font-size: 0.65rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 2px; }
            .field-value { font-size: 0.88rem; line-height: 1.5; }
            .chip { display: inline-block; background: #e0f2f1; color: #00695c; font-size: 0.7rem; font-weight: 700; padding: 3px 9px; border-radius: 9999px; margin: 2px 3px 2px 0; }
            table { width: 100%; border-collapse: collapse; font-size: 0.83rem; margin-top: 4px; }
            th { background: #f8fafc; text-align: left; padding: 7px 10px; font-size: 0.62rem; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.07em; border-bottom: 2px solid #e2e8f0; }
            td { padding: 7px 10px; border-bottom: 1px solid #f8fafc; vertical-align: top; }
            tr:last-child td { border-bottom: none; }
            .footer { text-align: center; font-size: 0.72rem; color: #94a3b8; padding: 16px; }
            @media print {
                body { background: white; padding: 0; }
                .page-hdr { border-radius: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
                .register { box-shadow: none; border-radius: 0; }
                .entry { page-break-inside: avoid; }
            }
        `;

        function chips(arr) {
            if (!arr || !arr.length) return '<span style="color:#94a3b8">—</span>';
            return arr.map(v => `<span class="chip">${esc(v)}</span>`).join('');
        }
        function processorsTable(procs) {
            if (!procs || !procs.length) return '<p style="font-size:0.85rem;color:#94a3b8;margin:4px 0">No processors declared.</p>';
            const rows = procs.map(p => `<tr><td><strong>${esc(p.name)}</strong></td><td>${esc(p.country)}</td><td>${esc(p.role)}</td><td style="color:#64748b">${esc(p.contact||'—')}</td></tr>`).join('');
            return `<table><thead><tr><th>Processor</th><th>Country</th><th>Role</th><th>Contact</th></tr></thead><tbody>${rows}</tbody></table>`;
        }
        function transfersTable(transfers) {
            if (!transfers || !transfers.length) return '<p style="font-size:0.85rem;color:#94a3b8;margin:4px 0">No cross-border transfers.</p>';
            const rows = transfers.map(t => `<tr><td><strong>${esc(t.destination_country)}</strong></td><td>${esc(t.safeguard)}</td><td>${esc(t.processor||'—')}</td></tr>`).join('');
            return `<table><thead><tr><th>Destination</th><th>Safeguard</th><th>Processor</th></tr></thead><tbody>${rows}</tbody></table>`;
        }
        function parseJ(v) { if (!v) return []; if (Array.isArray(v)) return v; try { return JSON.parse(v); } catch(e) { return []; } }

        function entryBlock(e) {
            const cats       = parseJ(e.data_categories);
            const subjects   = parseJ(e.data_subject_categories);
            const procs      = parseJ(e.processors);
            const transfers  = parseJ(e.cross_border_transfers);
            const policies   = parseJ(e.linked_policy_ids);
            const retDays    = esc(e.retention_period_days || '—');
            const retYears   = e.retention_period_days ? `(≈ ${esc((e.retention_period_days/365).toFixed(1))} yrs)` : '';
            return `
            <div class="entry">
              <div class="entry-hdr">
                <div>
                  <div class="entry-title">${esc(e.activity_name)}</div>
                  <div style="font-size:0.78rem;color:#64748b;margin-top:3px">v${esc(e.version)} &nbsp;·&nbsp; DPO: ${esc(e.dpo_id||'—')}</div>
                </div>
                <div><span class="badge badge-active">ACTIVE</span> &nbsp;<span class="badge badge-consent">${esc((e.legal_basis||'').toUpperCase())}</span></div>
              </div>

              <div class="section-title">Purpose</div>
              <p style="font-size:0.88rem;margin:0;line-height:1.6">${esc(e.purpose||'—')}</p>

              <div class="section-title">Data Subject Categories</div>
              ${chips(subjects)}

              <div class="section-title">Data Categories (${cats.length})</div>
              ${chips(cats)}

              <div class="section-title">Security Measures</div>
              <p style="font-size:0.88rem;margin:0;line-height:1.6">${esc(e.security_measures||'—')}</p>

              <div class="section-title">Processors (${procs.length})</div>
              ${processorsTable(procs)}

              <div class="section-title">Cross-Border Transfers</div>
              ${transfersTable(transfers)}

              <div class="section-title">Retention &amp; Policy</div>
              <div class="field-grid">
                <div><div class="field-label">Retention Period</div><div class="field-value">${retDays} days ${retYears}</div></div>
                <div><div class="field-label">Start Event</div><div class="field-value">${esc(e.retention_start_event||'—')}</div></div>
                <div style="grid-column:span 2"><div class="field-label">Linked Policies</div><div class="field-value">${chips(policies)}</div></div>
              </div>

              <div class="section-title">Consent Summary</div>
              <div class="field-grid">
                <div><div class="field-label">Active Consents</div><div class="field-value">${esc(e.consent_count != null ? e.consent_count : 0)}</div></div>
                <div><div class="field-label">Withdrawn Consents</div><div class="field-value">${esc(e.inactive_consent_count != null ? e.inactive_consent_count : 0)}</div></div>
              </div>
            </div>`;
        }

        // Group entries by first linked policy
        const pdfGroups = {};
        entries.forEach(e => {
            const key = parseJ(e.linked_policy_ids)[0] || '__none__';
            if (!pdfGroups[key]) pdfGroups[key] = [];
            pdfGroups[key].push(e);
        });
        const pdfKeys = Object.keys(pdfGroups).filter(k => k !== '__none__').sort();
        if (pdfGroups['__none__']) pdfKeys.push('__none__');
        const policyCount = pdfKeys.filter(k => k !== '__none__').length;

        const entryBlocks = pdfKeys.map(key => {
            const group = pdfGroups[key];
            const label = key === '__none__' ? 'Other Processing Activities' : key;
            const hdr = `<div style="background:#f0fdfa;border-left:4px solid #0d9488;padding:10px 20px;margin:8px 0 0;">
              <span style="font-size:0.6rem;font-weight:800;color:#0d9488;text-transform:uppercase;letter-spacing:0.1em">Policy</span>
              <span style="font-family:monospace;font-weight:700;color:#134e4a;margin-left:8px">${esc(label)}</span>
              <span style="font-size:0.75rem;color:#5eead4;margin-left:10px">${group.length} activit${group.length===1?'y':'ies'}</span>
            </div>`;
            return hdr + group.map(entryBlock).join('');
        }).join('');

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ROPA Register — ${esc(fiduciary)}</title>
  <style>${css}</style>
</head>
<body>
  <div class="page-hdr">
    <div class="page-hdr-label">DPDP Act, 2023 &nbsp;·&nbsp; Records of Processing Activities &nbsp;·&nbsp; Active Entries Only</div>
    <h1>ROPA Register — ${esc(fiduciary)}</h1>
    <p>Generated: ${esc(generated)}&nbsp;·&nbsp; ${entries.length} activit${entries.length===1?'y':'ies'} across ${policyCount} polic${policyCount===1?'y':'ies'}</p>
  </div>
  <div class="register">${entryBlocks}</div>
  <div class="footer">Generated by TSI DPDP CMS &nbsp;·&nbsp; ${esc(generated)}</div>
</body>
</html>`;

        const printWin = window.open('', '_blank', 'width=1000,height=800');
        printWin.document.write(html);
        printWin.document.close();
        printWin.addEventListener('load', () => {
            printWin.focus();
            printWin.print();
        });
    }

    // ---- Helpers ----
    function prettyJson(val) {
        if (val == null) return '—';
        if (typeof val === 'string') {
            try { return JSON.stringify(JSON.parse(val), null, 0); } catch(e) { return val; }
        }
        return JSON.stringify(val);
    }

    // ---- Init ----
    document.addEventListener('DOMContentLoaded', () => {
        const user = localStorage.getItem('username');
        if (user) document.getElementById('username').textContent = user;
        if (!FIDUCIARY_ID) { alert('No fiduciary session found. Please log in.'); handleLogout(); return; }
        if (POLICY_FILTER) {
            document.getElementById('policy-filter-label').textContent = POLICY_FILTER;
            document.getElementById('policy-filter-banner').classList.remove('hidden');
        }
        loadEntries();
    });

    window.viewEntry   = viewEntry;
    window.retireEntry = retireEntry;
    window.exportRopa  = exportRopa;
