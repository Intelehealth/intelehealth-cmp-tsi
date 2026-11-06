// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        toggleSidebar: () => toggleSidebar(),
        handleLogout: () => handleLogout(),
        showUserModal: (el) => showUserModal(el.getAttribute('data-arg')),
        closeModals: () => closeModals(),
        copyPassphrase: () => copyPassphrase(),
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

    const API_USERS = '/api/v1/admin/operator';
    const AUTH_TOKEN = localStorage.getItem('authToken');

    // Team management is a DPO/ADMIN delegation tool -- Operators have no one to delegate to.
    if (localStorage.getItem('role') === 'OPERATOR') {
        window.location.href = 'dashboard.html';
    }

    document.getElementById('username').textContent = localStorage.getItem('username') || 'DPO User';

    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('backdrop').classList.toggle('active');
    }

    async function loadUsers() {
        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_users" })
            });
            const users = await res.json();
            if (users.status === 401) {
                alert("Session Expired: Authentication required");
                handleLogout();
                return;
            }
            // This DPO's own fiduciary may also contain DPO/ADMIN accounts -- Team only manages Operators.
            const operators = users.filter(u => u.role === 'OPERATOR');

            const tbody = document.getElementById('user-table-body');

            if (operators.length === 0) {
                tbody.innerHTML = `
                <tr>
                    <td colspan="4" class="px-4 py-12 text-center">
                        <p class="text-sm font-bold text-slate-500">No Operators yet</p>
                        <p class="text-xs text-slate-400 mt-1">Add an Operator to delegate grievance and compliance closure work.</p>
                    </td>
                </tr>`;
            } else {
                tbody.innerHTML = operators.map(u => {
                    const isInactive = u.status === 'INACTIVE';
                    const statusColor = isInactive ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700';

                    let actionsHtml = '';
                    if (isInactive) {
                        actionsHtml = `<span class="text-[9px] font-black text-slate-400 uppercase tracking-tighter italic self-center">Account Locked</span>`;
                    } else {
                        actionsHtml += `<button data-action="edit" data-user-id="${esc(u.user_id)}" class="text-indigo-600 font-bold hover:underline text-xs">Edit</button>`;
                        actionsHtml += `<button data-action="recovery" data-user-id="${esc(u.user_id)}" class="text-amber-600 font-black hover:underline text-[10px] uppercase tracking-tighter">Recovery Key</button>`;
                        actionsHtml += `<button data-action="deactivate" data-user-id="${esc(u.user_id)}" class="text-red-500 font-bold hover:underline text-xs">Deactivate</button>`;
                    }

                    return `
                    <tr class="hover:bg-slate-50 transition-colors">
                        <td class="px-4 py-4 font-bold text-slate-700">${esc(u.username)}</td>
                        <td class="px-4 py-4 text-xs text-slate-500">${esc(u.email)}</td>
                        <td class="px-4 py-4"><span class="px-3 py-1 text-[10px] font-black rounded-full ${statusColor} uppercase">${esc(u.status)}</span></td>
                        <td class="px-4 py-4 flex items-center gap-3">
                            ${actionsHtml}
                        </td>
                    </tr>
                `}).join('');
            }
            document.getElementById('user-count').textContent = `Total: ${operators.length} Operator(s)`;
        } catch (e) { console.error("Load failed", e); }
    }

    async function editUser(id) {
        showUserModal('Edit Operator', true);
        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_user", "user_id": id })
            });
            const u = await res.json();
            document.getElementById('user-id-hidden').value = u.user_id;
            document.getElementById('user-name').value = u.username;
            document.getElementById('user-email').value = u.email;
        } catch (e) { alert("Load Failed"); }
    }

    async function deactivateUser(id) {
        if (!confirm("Are you sure you want to deactivate this Operator?")) return;
        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "deactivate_user", "user_id": id })
            });
            if (res.ok) loadUsers();
            else alert("Failed to deactivate Operator.");
        } catch (e) { alert("Action failed"); }
    }

    async function requestRecoveryKey(userId) {
        if (!confirm("Initiate Master Recovery Key generation? This will rotate the existing key for this Operator.")) return;

        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "generate_recovery_key", "user_id": userId })
            });
            const data = await res.json();
            if (data.success) {
                document.getElementById('plain-passphrase').textContent = data.passphrase;
                document.getElementById('recovery-modal').style.display = 'flex';
            } else { alert("Failed to generate key: " + data.message); }
        } catch (e) { alert("Registry communication error."); }
    }

    function copyPassphrase() {
        const text = document.getElementById('plain-passphrase').innerText;
        const dummy = document.createElement("textarea");
        document.body.appendChild(dummy);
        dummy.value = text;
        dummy.select();
        document.execCommand("copy");
        document.body.removeChild(dummy);
        alert("Copied to clipboard!");
    }

    function showUserModal(title) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('user-form').reset();
        document.getElementById('user-id-hidden').value = '';
        document.getElementById('user-modal').style.display = 'flex';
    }

    document.getElementById('user-form').onsubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData.entries());
        const isEdit = !!document.getElementById('user-id-hidden').value;

        // Role and fiduciary are never sent as caller-controlled values here: the server
        // forces role=OPERATOR and fiduciary_id=caller's own fiduciary for DPO callers.
        const payload = {
            "_func": isEdit ? "update_user" : "create_user",
            "user_id": document.getElementById('user-id-hidden').value,
            "username": data.name,
            "email": data.email,
            "role": "OPERATOR",
            "password": data.password
        };

        const res = await fetch(API_USERS, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
            body: JSON.stringify(payload)
        });

        if (res.ok) { closeModals(); loadUsers(); }
        else {
            const err = await res.json().catch(() => ({}));
            alert("Failed to save: " + (err.message || "Unknown error"));
        }
    };

    function closeModals() {
        document.querySelectorAll('.modal-overlay').forEach(m => m.style.display = 'none');
    }

    function handleLogout() {
        localStorage.clear();
        window.location.href = "../index.html";
    }

    // Row actions use data-* attributes + delegation instead of inline onclick (CF-02).
    document.getElementById('user-table-body').addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const id = btn.getAttribute('data-user-id');
        const action = btn.getAttribute('data-action');
        if (action === 'edit') editUser(id);
        else if (action === 'recovery') requestRecoveryKey(id);
        else if (action === 'deactivate') deactivateUser(id);
    });

    loadUsers();
