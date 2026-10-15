// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
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
    const API_FIDUCIARIES = '/api/v1/admin/fiduciary';
    const TOKEN = localStorage.getItem('authToken');
    let FiduciaryList = {};

    document.getElementById('username-display').textContent = localStorage.getItem('username') || 'Admin User';

    /**
     * Loads Fiduciaries for mapping IDs to names in the table and dropdown.
     */
    async function fetchFiduciaries() {
        try {
            const res = await fetch(API_FIDUCIARIES, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
                body: JSON.stringify({ "_func": "list_fiduciaries" })
            });
            const data = await res.json();
            const list = data.data || data;

            const select = document.getElementById('fiduciary-select');
            select.innerHTML = '<option value="">-- Global Access --</option>';

            list.forEach(f => {
                FiduciaryList[f.fiduciary_id] = f.name;
                const opt = document.createElement('option');
                opt.value = f.fiduciary_id;
                opt.textContent = f.name;
                select.appendChild(opt);
            });
        } catch (e) { console.error("Fiduciary load failed", e); }
    }

    async function loadUsers(search = "") {
        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
                body: JSON.stringify({ "_func": "list_users", "search": search })
            });
            const users = await res.json();
            if (users.status === 401) {
              alert("Session Expired: Authentication required");
              handleLogout();
              return;
           }
            const tbody = document.getElementById('user-table-body');
            tbody.innerHTML = users.map(u => {
                const isAdmin = u.role === 'ADMIN';
                const isInactive = u.status === 'INACTIVE';
                const fiduciaryName = FiduciaryList[u.fiduciary_id] || u.fiduciary_id || 'Global Access';

                // Status Badge logic
                const statusColor = isInactive ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700';

                // Action logic: If inactive, all options disabled
                let actionsHtml = '';
                if (isInactive) {
                    actionsHtml = `<span class="text-[9px] font-black text-slate-400 uppercase tracking-tighter italic self-center">Account Locked</span>`;
                } else {
                    if (!isAdmin) {
                        actionsHtml += `<button data-action="edit" data-user-id="${esc(u.user_id)}" class="text-indigo-600 font-bold hover:underline text-xs">Edit</button>`;
                    }
                    actionsHtml += `<button data-action="recovery" data-user-id="${esc(u.user_id)}" class="text-amber-600 font-black hover:underline text-[10px] uppercase tracking-tighter">Recovery Key</button>`;
                    if (!isAdmin) {
                        actionsHtml += `<button data-action="deactivate" data-user-id="${esc(u.user_id)}" class="text-red-500 font-bold hover:underline text-xs">Deactivate</button>`;
                    } else {
                        actionsHtml += `<span class="text-[9px] font-black text-slate-300 uppercase tracking-tighter italic self-center">System Protected</span>`;
                    }
                }

                return `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-4 font-bold text-slate-700">${esc(u.username)}</td>
                    <td class="px-4 py-4 text-xs font-black text-slate-400 uppercase">${esc(u.role)}</td>
                    <td class="px-4 py-4 text-xs text-slate-500">${esc(fiduciaryName)}</td>
                    <td class="px-4 py-4"><span class="px-3 py-1 text-[10px] font-black rounded-full ${statusColor} uppercase">${esc(u.status)}</span></td>
                    <td class="px-4 py-4 flex items-center gap-3">
                        ${actionsHtml}
                    </td>
                </tr>
            `}).join('');
            document.getElementById('user-count').textContent = `Total: ${users.length} Operators`;
        } catch (e) { console.error("Load failed", e); }
    }

    async function editUser(id) {
        showUserModal('Edit CMS User', true);
        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
                body: JSON.stringify({ "_func": "get_user", "user_id": id })
            });
            const u = await res.json();
            document.getElementById('user-id-hidden').value = u.user_id;
            document.getElementById('user-name').value = u.username;
            document.getElementById('user-email').value = u.email;
            document.getElementById('fiduciary-select').value = u.fiduciary_id || '';
        } catch (e) { alert("Load Failed"); }
    }

    async function deactivateUser(id) {
        if (!confirm("Are you sure you want to deactivate this operator?")) return;
        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
                body: JSON.stringify({ "_func": "deactivate_user", "user_id": id })
            });
            if (res.ok) loadUsers();
        } catch (e) { alert("Action failed"); }
    }

    async function requestRecoveryKey(userId) {
        if (!confirm("Initiate Master Recovery Key generation? This will rotate the existing key for this operator.")) return;

        try {
            const res = await fetch(API_USERS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
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

    function showUserModal(title, isEdit = false) {
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

        const payload = {
            "_func": isEdit ? "update_user" : "create_user",
            "user_id": document.getElementById('user-id-hidden').value,
            "username": data.name,
            "email": data.email,
            "role": data.role,
            "fiduciary_id": data.fiduciary_id,
            "password": data.password
        };

        const res = await fetch(API_USERS, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${TOKEN}` },
            body: JSON.stringify(payload)
        });

        if (res.ok) { closeModals(); loadUsers(); }
        else { alert("Failed to save."); }
    };

    function closeModals() {
        document.querySelectorAll('.modal-overlay').forEach(m => m.style.display = 'none');
    }

    function handleLogout() {
        localStorage.clear();
        window.location.href = "../index.html";
    }

    // Row actions (delegated; ids travel in data-* attributes, not inline JS)
    document.getElementById('user-table-body').addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const id = btn.getAttribute('data-user-id');
        const action = btn.getAttribute('data-action');
        if (action === 'edit') editUser(id);
        else if (action === 'recovery') requestRecoveryKey(id);
        else if (action === 'deactivate') deactivateUser(id);
    });

    window.onload = async () => {
        await fetchFiduciaries();
        loadUsers();
    };
