    const params = new URLSearchParams(window.location.search);
    const preselectedFid = params.get('fid');
    const preselectedPersona = params.get('persona');
    let selectedFiduciaryId = null;
    let selectedOtpMode = 'DUMMY_OTP';
    let otpRequested = false;
    let selectedPersonaId = null;
    let personaList = [];

    function updateOtpModeUi() {
        const sendOtpRow = document.getElementById('send-otp-row');
        const hint = document.getElementById('otp-hint');
        const loginBtn = document.getElementById('login-btn');
        const userIdLabel = document.getElementById('user-id-label');
        const userIdInput = document.getElementById('user-id');
        const otpLabel = document.getElementById('otp-label');
        otpRequested = false;

        if (selectedOtpMode === 'EMAIL_OTP') {
            userIdLabel.textContent = 'Email';
            userIdInput.type = 'email';
            userIdInput.placeholder = 'e.g. you@example.com';
            userIdInput.autocomplete = 'email';
            otpLabel.textContent = 'Email OTP';
        } else if (selectedOtpMode === 'MOBILE_OTP') {
            userIdLabel.textContent = 'Mobile Number';
            userIdInput.type = 'tel';
            userIdInput.placeholder = 'e.g. +91 98765 43210';
            userIdInput.autocomplete = 'tel';
            otpLabel.textContent = 'Mobile OTP';
        } else {
            userIdLabel.textContent = 'Data Principal Id';
            userIdInput.type = 'text';
            userIdInput.placeholder = 'e.g. you@example.com or +91 98765 43210';
            userIdInput.autocomplete = 'username';
            otpLabel.textContent = 'Dummy OTP';
        }

        if (selectedOtpMode === 'DUMMY_OTP') {
            sendOtpRow.style.display = 'none';
            hint.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Evaluation mode — use OTP <strong style="font-family:monospace;letter-spacing:0.1em;">1234</strong> to log in.';
            loginBtn.disabled = false;
        } else {
            sendOtpRow.style.display = 'block';
            const channel = selectedOtpMode === 'EMAIL_OTP' ? 'email' : 'mobile number';
            hint.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Click "Send OTP" to receive a one-time code on your ${channel}.`;
            loginBtn.disabled = true;
        }
    }

    document.getElementById('send-otp-btn').addEventListener('click', async () => {
        const userId = document.getElementById('user-id').value.trim();
        if (!selectedFiduciaryId) return showError('Please select an organisation.');
        if (!userId) return showError('Please enter your email or mobile number.');
        hideError();

        const btn = document.getElementById('send-otp-btn');
        btn.disabled = true;
        btn.textContent = 'Sending...';
        try {
            await publicApiCall('/api/v1/public/principal', 'request_principal_otp', {
                fiduciary_id: selectedFiduciaryId,
                user_id: userId
            });
            otpRequested = true;
            document.getElementById('login-btn').disabled = false;
            const channel = selectedOtpMode === 'EMAIL_OTP' ? 'email' : 'mobile number';
            document.getElementById('otp-hint').innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>OTP sent to your ${channel}. Enter it below.`;
        } catch (e) {
            showError('Could not send OTP. Please try again.');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Send OTP';
        }
    });

    function showError(msg) {
        const el = document.getElementById('login-error');
        el.textContent = msg;
        el.style.display = 'block';
    }

    function hideError() {
        document.getElementById('login-error').style.display = 'none';
    }

    function showForm() {
        document.getElementById('login-form').style.display = 'block';
    }

    // ── Persona selection (who is logging in: Customer, Employee, Vendor...) ──
    async function loadPersonas(fiduciaryId) {
        const wrapper = document.getElementById('persona-wrapper');
        const section = document.getElementById('persona-section');
        selectedPersonaId = null;
        document.getElementById('login-form').style.display = 'none';

        try {
            personaList = await publicApiCall('/api/v1/public/principal', 'list_fiduciary_personas', { fiduciary_id: fiduciaryId });
            if (!Array.isArray(personaList)) personaList = personaList.data || [];
            // Drop malformed entries -- a persona with no id/label renders as a blank
            // pill the user can't recognise, and would keep the login form hidden.
            personaList = personaList.filter(p => p && p.id && p.label);
        } catch (e) {
            personaList = [];
        }

        if (personaList.length === 0) {
            // Nothing meaningful to ask -- proceed straight to credentials.
            wrapper.style.display = 'none';
            showForm();
            return;
        }

        renderPersonaPills(section);
        wrapper.style.display = 'block';

        if (preselectedPersona && personaList.find(p => p.id === preselectedPersona)) {
            selectPersona(preselectedPersona);
        }
    }

    function renderPersonaPills(section) {
        section.innerHTML = `<div style="display:flex;gap:8px;flex-wrap:wrap;">${
            personaList.map(p => `<button type="button" class="persona-pill" data-persona-id="${esc(p.id)}"
                style="padding:8px 18px;border-radius:20px;font-size:0.85rem;font-weight:700;cursor:pointer;
                border:2px solid ${p.id === selectedPersonaId ? 'var(--tsi-primary)' : '#e2e8f0'};
                background:${p.id === selectedPersonaId ? 'var(--tsi-primary)' : 'white'};
                color:${p.id === selectedPersonaId ? 'white' : '#475569'};transition:all 0.2s;">${esc(p.label)}</button>`).join('')
        }</div>`;
        section.querySelectorAll('.persona-pill').forEach(btn => {
            btn.addEventListener('click', () => selectPersona(btn.dataset.personaId));
        });
    }

    function selectPersona(personaId) {
        selectedPersonaId = personaId;
        renderPersonaPills(document.getElementById('persona-section'));
        hideError();
        showForm();
    }

    async function loadFiduciaries() {
        const section = document.getElementById('fiduciary-section');
        try {
            const data = await publicApiCall('/api/v1/public/principal', 'list_active_fiduciaries');
            const list = Array.isArray(data) ? data : (data.data || []);

            if (preselectedFid) {
                const match = list.find(f => f.fiduciary_id === preselectedFid);
                if (!match) {
                    section.innerHTML = `<div style="color:#b91c1c;background:#fef2f2;border-radius:8px;padding:12px;font-size:0.875rem;margin-bottom:20px;">Fiduciary not found or inactive.</div>`;
                    return;
                }
                selectedFiduciaryId = preselectedFid;
                selectedOtpMode = match.otp_mode || 'DUMMY_OTP';
                section.innerHTML = `
                    <div class="fiduciary-badge">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#006A67" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                        <div>
                            <div style="font-size:0.7rem;color:#64748b;font-weight:700;text-transform:uppercase;">Organisation</div>
                            <div style="font-size:0.95rem;font-weight:700;color:#0f172a;">${esc(match.name)}</div>
                        </div>
                    </div>
                `;
            } else {
                if (list.length === 0) {
                    section.innerHTML = `<div style="color:#64748b;font-size:0.875rem;margin-bottom:20px;text-align:center;">No organisations registered yet.</div>`;
                    return;
                }
                section.innerHTML = `
                    <label for="fid-select">Select Organisation</label>
                    <select id="fid-select">
                        <option value="">— Choose your organisation —</option>
                        ${list.map(f => `<option value="${esc(f.fiduciary_id)}">${esc(f.name)}</option>`).join('')}
                    </select>
                `;
                document.getElementById('fid-select').addEventListener('change', function() {
                    selectedFiduciaryId = this.value || null;
                    const selected = list.find(f => f.fiduciary_id === selectedFiduciaryId);
                    selectedOtpMode = selected ? (selected.otp_mode || 'DUMMY_OTP') : 'DUMMY_OTP';
                    updateOtpModeUi();
                    if (selectedFiduciaryId) {
                        loadPersonas(selectedFiduciaryId);
                    } else {
                        document.getElementById('persona-wrapper').style.display = 'none';
                        document.getElementById('login-form').style.display = 'none';
                    }
                });
            }
            updateOtpModeUi();
            if (selectedFiduciaryId) await loadPersonas(selectedFiduciaryId);
        } catch (e) {
            section.innerHTML = `<div style="color:#b91c1c;font-size:0.875rem;margin-bottom:20px;">Could not load organisations. Please try again.</div>`;
        }
    }

    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        hideError();

        if (!selectedFiduciaryId) {
            showError('Please select an organisation.');
            return;
        }
        if (personaList.length > 0 && !selectedPersonaId) {
            showError('Please tell us who you are logging in as.');
            return;
        }

        const userId = document.getElementById('user-id').value.trim();
        const otp    = document.getElementById('otp').value;
        const btn    = document.getElementById('login-btn');

        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>Verifying...';

        const loginBody = { fiduciary_id: selectedFiduciaryId, user_id: userId, otp: otp };
        if (selectedPersonaId) loginBody.persona = selectedPersonaId;

        try {
            const res = await publicApiCall('/api/v1/public/principal', 'principal_login', loginBody);

            if (res && res.success && res.token) {
                saveSession(res);
                window.location.href = 'dashboard.html';
            } else {
                const msg = (res && res.message) ? res.message : 'Invalid OTP or account not found. Please try again.';
                showError(msg);
            }
        } catch (err) {
            showError('Network error. Please check your connection and try again.');
        } finally {
            btn.disabled = false;
            btn.innerHTML = 'Access My Dashboard';
        }
    });

    document.addEventListener('DOMContentLoaded', () => {
        if (getSession()) {
            window.location.href = 'dashboard.html';
            return;
        }
        loadFiduciaries();
    });
