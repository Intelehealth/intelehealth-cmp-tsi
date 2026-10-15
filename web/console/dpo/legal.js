// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        loadCertificates: () => loadCertificates(),
        print: () => window.print(),
        closeModal: () => closeModal(),
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

    // --- Setup & Connectivity ---
    const API_URL = ENV_SERVER_URL + '/api/v1/admin/legal';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    if (localStorage.getItem('role') === 'OPERATOR') {
        document.querySelectorAll('a[href="policies.html"], a[href="settings.html"], a[href="team.html"]').forEach(el => el.remove());
        document.getElementById('evidence-form-card').style.display = 'none'; // hidden, not removed: init below still wires the (now invisible) form's submit handler
    }

    /**
     * Fetches the full list of previously crystallized certificates.
     */
    async function loadCertificates() {
        const tbody = document.getElementById('cert-table-body');
        tbody.innerHTML = '<tr><td colspan="5" class="py-12 text-center text-slate-400 font-medium animate-pulse uppercase tracking-widest text-xs">Querying Secure Registry...</td></tr>';

        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_certificates", "fiduciary_id": FIDUCIARY_ID })
            });

            if (response.ok) {
                const list = await response.json();
                if(list.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="py-12 text-center text-slate-400">No certified artifacts found in this fiduciary context.</td></tr>';
                    return;
                }
                tbody.innerHTML = list.map(c => `
                    <tr class="hover:bg-teal-50/30 transition-colors group">
                        <td class="py-4 px-2 font-mono text-[11px] text-slate-500">...${esc(c.id.slice(-12).toUpperCase())}</td>
                        <td class="py-4 px-2 font-bold text-slate-700 text-xs">${esc(c.principal_id)}</td>
                        <td class="py-4 px-2 text-slate-600 font-medium text-xs underline decoration-dotted">${esc(c.case_ref || 'GENERAL_TRACE')}</td>
                        <td class="py-4 px-2 text-slate-400 text-[10px] font-bold">${esc(new Date(c.timestamp).toLocaleString())}</td>
                        <td class="py-4 px-2 text-right">
                            <button data-cert-id="${esc(c.id)}" class="bg-slate-100 text-slate-600 px-3 py-1 rounded-lg font-black hover:bg-teal-600 hover:text-white text-[9px] uppercase tracking-tighter transition-all">Open Viewer</button>
                        </td>
                    </tr>
                `).join('');
            }
        } catch (e) { 
            tbody.innerHTML = '<tr><td colspan="5" class="py-12 text-center text-red-500 font-black">Registry Connection Failed.</td></tr>'; 
        }
    }

    // Viewer buttons use data-cert-id + delegation instead of inline onclick (CF-02).
    document.getElementById('cert-table-body').addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-cert-id]');
        if (btn) viewCertificate(btn.getAttribute('data-cert-id'));
    });

    /**
     * Retrieves and renders a specific certificate with its hash-chained trail.
     */
    async function _viewCertificate(id) {
        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_certificate", "id": id })
            });
            const cert = await response.json();
            
            // Backend returns 'data' as a JSON string
            const data = typeof cert.data === 'string' ? JSON.parse(cert.data) : cert.data;

            document.getElementById('view-cert-id').textContent = cert.id.toUpperCase();
            document.getElementById('view-principal').textContent = data.principal_id;
            
            // Display Inquiry Reference defaulting to requested value
            document.getElementById('view-case').textContent = data.case_ref_id;
            
            // Map Issuing Fiduciary properly
            document.getElementById('view-fiduciary').textContent = data.fiduciary_name;
            
            document.getElementById('view-attestation').textContent = cert.attestation;

            // System Provenance
            const env = data.system_metadata || {};
            document.getElementById('view-ip').textContent = env.server_ip || 'Internal';
            document.getElementById('view-mac').textContent = env.mac_address || '---';
            document.getElementById('view-os').textContent = (env.os_name || 'System') + " (" + (env.os_version || 'v1') + ")";

            // Validated Chain Execution
            const trailBody = document.getElementById('view-trail-body');
            trailBody.innerHTML = (data.evidence_trail || []).map(t => `
                <tr class="hover:bg-slate-50">
                    <td class="p-2 font-mono text-slate-500">${esc(t.ts)}</td>
                    <td class="p-2 font-black text-slate-800 uppercase tracking-tighter">${esc(t.act)}</td>
                    <td class="p-2 font-mono text-teal-700 break-all border-l border-slate-100">${esc(t.hash)}</td>
                </tr>
            `).join('');

            document.getElementById('cert-modal').style.display = 'flex';
        } catch (e) { 
            console.error(e);
            alert("Digital artifact retrieval failed. Verify connectivity."); 
        }
    }

    /**
     * Form Handler to initiate the crystallization process.
     */
    document.getElementById('evidence-form').onsubmit = async (e) => {
        e.preventDefault();
        const btn = document.getElementById('generate-btn');
        const userIdInput = document.getElementById('target-user-id');
        const caseRefInput = document.getElementById('case-ref');

        btn.disabled = true;
        btn.innerHTML = `<svg class="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg> Cryptographic Signing...`;

        const payload = {
            "_func": "generate_certificate",
            "subject_principal_id": userIdInput.value.trim(),
            "fiduciary_id": FIDUCIARY_ID,
            "case_ref_id": caseRefInput.value.trim(),
            "attestation_text": document.getElementById('attestation-text') ? document.getElementById('attestation-text').value.trim() : undefined
        };

        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const res = await response.json();
                loadCertificates();
                viewCertificate(res.certificate_id);
                userIdInput.value = '';
                caseRefInput.value = '';
            } else { 
                const err = await response.json();
                alert("Generation Error: " + (err.message || "Ensure the principal has an audit history.")); 
            }
        } catch (e) { alert("Registry Network Error."); }
        finally {
            btn.disabled = false;
            btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg> Sign & Issue Certificate`;
        }
    };

    function closeModal() { document.getElementById('cert-modal').style.display = 'none'; }

    // SEC-10: the console can now re-verify a certificate's signature AND its
    // embedded trail against the live audit ledger (constant-time compare and
    // chain re-derivation live in the API), so the DPO does not have to trust
    // the printed document.
    let CURRENT_CERT_ID = null;
    function viewCertificate(id) { CURRENT_CERT_ID = id; _viewCertificate(id); }

    document.getElementById('verify-cert-btn').addEventListener('click', async () => {
        if (!CURRENT_CERT_ID) { alert("Open a certificate first."); return; }
        const btn = document.getElementById('verify-cert-btn');
        btn.disabled = true;
        btn.innerHTML = 'Verifying...';
        try {
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "verify_certificate", "id": CURRENT_CERT_ID })
            });
            const res = await response.json();
            alert(
                res.valid
                    ? `Certificate VERIFIED.\nSignature: ${res.signature_algorithm || 'HMAC-SHA256'}\nTrail hashes checked: ${res.trail_hashes_checked ?? 0}\nChain intact: ${res.chain_intact === true ? 'YES' : 'NO'}`
                    : `Certificate FAILED verification:\n${res.reason || 'invalid'}` + (res.broken_count != null ? `\nChain breaks: ${res.broken_count}` : '')
            );
        } catch (err) {
            alert("Verification request failed: " + err);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>\n                Verify Integrity';
        }
    });
    function handleLogout() { localStorage.clear(); window.location.href = "../index.html"; }

    window.onload = () => {
        // Dynamically populating the Officer Identification from the logged-in session
        const currentUserName = localStorage.getItem('username') || 'AUTHORIZED_OFFICER';
        document.getElementById('officer-name').value = currentUserName;
        document.getElementById('username-display').textContent = currentUserName;
        loadCertificates();
    };
