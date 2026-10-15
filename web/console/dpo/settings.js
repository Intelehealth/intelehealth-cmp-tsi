// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
        addBreachType: () => addBreachType(),
        addNotificationLanguage: () => addNotificationLanguage(),
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

    const API_URL_NOTIFICATION = '/api/v1/admin/notification';
    const API_URL_POLICY = '/api/v1/admin/policy';
    if (localStorage.getItem('role') === 'OPERATOR') {
        window.location.href = 'dashboard.html';
    }
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const FIDUCIARY_ID = localStorage.getItem('fiduciary_id');
    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'DPO User';

    // NT-02: exactly the notification types the services write, so a localised
    // message is the one the delivery engine looks up. `placeholders` are the
    // {fields} the notice is filled with. Breach categories are managed below.
    const NOTIFICATION_TYPES = [
        { type: 'CONSENT_GIVEN_NOTIFICATION', label: 'Consent Given' },
        { type: 'WITHDRAWAL_ACKNOWLEDGMENT', label: 'Consent Withdrawn' },
        { type: 'ERASURE_REQUESTED_NOTIFICATION', label: 'Erasure Requested' },
        { type: 'CONSENT_VALIDATION_DENIED', label: 'Processing Denied (no active consent)' },
        { type: 'POLICY_CHANGE_RECONSENT_REQUIRED', label: 'Notice Changed - Re-consent Required' },
        { type: 'PURPOSE_CLOSED', label: 'Purpose Ended' },
        { type: 'GRIEVANCE_SUBMITTED', label: 'Grievance Submitted', placeholders: ['reference_number'] },
        { type: 'GRIEVANCE_ASSIGNED', label: 'Grievance Assigned' },
        { type: 'GRIEVANCE_IN_PROGRESS', label: 'Grievance In Progress' },
        { type: 'GRIEVANCE_ESCALATED', label: 'Grievance Escalated', placeholders: ['reference_number'] },
        { type: 'GRIEVANCE_RESOLVED', label: 'Grievance Resolved', placeholders: ['reference_number', 'status_word', 'resolution_details'] },
        { type: 'GRIEVANCE_ROUTED', label: 'Grievance Routed to Officer (staff)', placeholders: ['reference_number', 'grievance_type'] },
        { type: 'PURGE_SCHEDULED', label: 'Deletion Scheduled (DPO)' },
        { type: 'PURGE_EXECUTED', label: 'Deletion Requests Raised (DPO)' },
        { type: 'PURGE_OVERDUE', label: 'Deletion Overdue (DPO)' },
        { type: 'SECURITY_AUTH_FAILURE_BURST', label: 'Failed Sign-in Burst (DPO)', placeholders: ['failures', 'window_minutes'] },
        { type: 'BREACH_NOTIFICATION', label: 'Personal Data Breach', placeholders: ['title', 'description', 'likely_consequences', 'mitigation_measures', 'actionable_steps', 'contact_point', 'detected_at'] },
        { type: 'BREACH_BOARD_DEADLINE_DUE', label: 'Board Intimation Due (DPO)', placeholders: ['title', 'deadline'] },
        { type: 'BREACH_BOARD_DEADLINE_MISSED', label: 'Board Intimation Missed (DPO)', placeholders: ['title', 'deadline'] }
    ];
    const PLACEHOLDERS_BY_TYPE = Object.fromEntries(NOTIFICATION_TYPES.map(t => [t.type, t.placeholders || []]));

    const LANGUAGE_NAMES = { en: 'English', as: 'Assamese', bn: 'Bengali', brx: 'Bodo', doi: 'Dogri', gu: 'Gujarati', hi: 'Hindi', kn: 'Kannada', ks: 'Kashmiri', kok: 'Konkani', mai: 'Maithili', ml: 'Malayalam', mni: 'Manipuri', mr: 'Marathi', ne: 'Nepali', or: 'Odia', pa: 'Punjabi', sa: 'Sanskrit', sat: 'Santali', sd: 'Sindhi', ta: 'Tamil', te: 'Telugu', ur: 'Urdu' };
    const BREACH_TYPE_PREFIX = 'BREACH_NOTIFICATION_';
    const WEBHOOK_CATEGORIES = [
        { category: 'NOTIFICATION', label: 'Notification Webhook', description: 'Fires for every notification (consent, withdrawal, purge, breach, etc.) as it\'s created.' },
        { category: 'PURGE', label: 'Purge Webhook', description: 'Fires when a purge request is created or its status changes (e.g. completed, legal hold).' }
    ];

    let SUPPORTED_LANGUAGES = ['en'];

    function toggleMenu() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebar-backdrop').classList.toggle('hidden');
    }

    // NT-03: a notice may be written in English or any Eighth Schedule language,
    // not only the languages the active policy happens to carry.
    function languagesFor(policyLanguages, existingMessages) {
        const set = new Set(['en', ...policyLanguages]);
        Object.values(existingMessages || {}).forEach(m => Object.keys(m || {}).forEach(l => set.add(l)));
        return Object.keys(LANGUAGE_NAMES).filter(l => set.has(l));
    }

    function renderAddLanguage() {
        const select = document.getElementById('add-language-select');
        if (!select) return;
        const missing = Object.keys(LANGUAGE_NAMES).filter(l => !SUPPORTED_LANGUAGES.includes(l));
        select.innerHTML = '<option value="">Add a language...</option>' +
            missing.map(l => `<option value="${esc(l)}">${esc(LANGUAGE_NAMES[l])}</option>`).join('');
    }

    async function addNotificationLanguage() {
        const lang = document.getElementById('add-language-select').value;
        if (!lang) return;
        SUPPORTED_LANGUAGES = Object.keys(LANGUAGE_NAMES).filter(l => l === lang || SUPPORTED_LANGUAGES.includes(l));
        const existingMessages = await loadExistingMessages();
        renderSettingsForm(SUPPORTED_LANGUAGES, existingMessages);
        renderBreachTypes(SUPPORTED_LANGUAGES, existingMessages);
        renderAddLanguage();
    }

    async function loadSupportedLanguages() {
        try {
            const response = await fetch(API_URL_POLICY, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_active_policy", "fiduciary_id": FIDUCIARY_ID, "jurisdiction": "IN" })
            });
            const policy = await response.json();
            if (policy && policy.policy_content) {
                return Object.keys(policy.policy_content);
            }
        } catch (e) {
            console.error("Could not load active policy languages", e);
        }
        return ['en'];
    }

    // P12-07: legacy template text archived by db/27, keyed by the live type it
    // maps to. Shown read-only beside that type for the DPO to re-home by hand.
    const ARCHIVED_BY_TYPE = {};

    async function loadExistingMessages() {
        const messagesByType = {};
        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_notification_messages", "fiduciary_id": FIDUCIARY_ID })
            });
            const rows = await response.json();
            (rows || []).forEach(row => {
                messagesByType[row.notification_type] = row.messages;
                if (row.archived_legacy && row.archived_legacy.length) ARCHIVED_BY_TYPE[row.notification_type] = row.archived_legacy;
            });
        } catch (e) {
            console.error("Could not load existing notification messages", e);
        }
        return messagesByType;
    }

    // Derives a display label for a DPO-defined breach category from its code,
    // e.g. "BREACH_NOTIFICATION_PHISHING" -> "Phishing". No separate label storage.
    function breachTypeLabel(type) {
        const code = type.substring(BREACH_TYPE_PREFIX.length).toLowerCase();
        return code.charAt(0).toUpperCase() + code.slice(1);
    }

    function createTypeCard(type, label, languages, existing) {
        const card = document.createElement('div');
        card.className = 'card';

        const langInputs = languages.map(lang => `
            <div class="mb-2">
                <label class="block text-xs font-bold text-slate-500 uppercase mb-1">${esc(LANGUAGE_NAMES[lang] || lang)}</label>
                <input type="text" data-lang="${esc(lang)}" value="${esc(existing[lang] || '')}"
                       class="w-full p-2 border border-gray-300 rounded-md text-sm" placeholder="Message shown to the Data Principal in ${esc(LANGUAGE_NAMES[lang] || lang)}">
            </div>
        `).join('');

        const placeholders = PLACEHOLDERS_BY_TYPE[type] || [];
        const hint = placeholders.length
            ? `<p class="text-xs text-slate-500 mb-2">Fields you can use: ${placeholders.map(p => '<code>{' + esc(p) + '}</code>').join(' ')}</p>`
            : '';
        const archived = (ARCHIVED_BY_TYPE[type] || []).map(a => `
            <details class="mb-3 text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded-md p-2">
                <summary class="cursor-pointer font-medium">Archived legacy text (${esc(a.notification_type)}) - written for a different event; copy any wording you still need</summary>
                ${Object.entries(a.messages || {}).map(([lang, text]) => `<p class="mt-1"><span class="font-bold uppercase">${esc(lang)}</span>: ${esc(text)}</p>`).join('')}
            </details>`).join('');
        card.innerHTML = `
            <h2 class="text-md font-bold text-slate-700 mb-3 tracking-tight">${esc(label)}</h2>
            ${hint}
            ${archived}
            <div class="messages-form" data-type="${esc(type)}">${langInputs}</div>
            <div class="flex justify-end mt-2">
                <button class="save-message-btn primary-bg text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-opacity-90">Save</button>
            </div>
        `;
        card.querySelector('.save-message-btn').addEventListener('click', () => saveMessage(type));
        return card;
    }

    function renderSettingsForm(languages, existingMessages) {
        const container = document.getElementById('settings-container');
        container.innerHTML = '';
        NOTIFICATION_TYPES.forEach(({ type, label }) => {
            container.appendChild(createTypeCard(type, label, languages, existingMessages[type] || {}));
        });
    }

    function renderBreachTypes(languages, existingMessages) {
        const container = document.getElementById('breach-types-container');
        container.innerHTML = '';
        Object.keys(existingMessages)
            .filter(type => type.startsWith(BREACH_TYPE_PREFIX))
            .sort()
            .forEach(type => {
                container.appendChild(createTypeCard(type, breachTypeLabel(type), languages, existingMessages[type] || {}));
            });
    }

    function addBreachType() {
        const input = document.getElementById('new-breach-type-code');
        const code = input.value.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
        if (!code) return alert("Enter a short code for the breach type, e.g. 'phishing'.");
        const type = BREACH_TYPE_PREFIX + code;
        if (document.querySelector(`.messages-form[data-type="${type}"]`)) {
            return alert("That breach type already exists below.");
        }
        document.getElementById('breach-types-container').appendChild(
            createTypeCard(type, breachTypeLabel(type), SUPPORTED_LANGUAGES, {})
        );
        input.value = '';
    }

    async function saveMessage(type) {
        const formDiv = document.querySelector(`.messages-form[data-type="${CSS.escape(type)}"]`);
        const messages = {};
        formDiv.querySelectorAll('input[data-lang]').forEach(input => {
            if (input.value.trim()) messages[input.dataset.lang] = input.value.trim();
        });

        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "set_notification_message", "fiduciary_id": FIDUCIARY_ID, "notification_type": type, "messages": messages })
            });
            if (response.ok) {
                alert("Message saved for " + type.replace(/_/g, ' ') + ".");
            } else {
                const err = await response.json().catch(() => ({}));
                alert("Failed to save message: " + (err.message || response.status));
            }
        } catch (e) {
            alert("Network error while saving message.");
        }
    }

    async function loadWebhookConfigs() {
        const configsByCategory = {};
        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_webhook_configs", "fiduciary_id": FIDUCIARY_ID })
            });
            const rows = await response.json();
            (rows || []).forEach(row => { configsByCategory[row.category] = row; });
        } catch (e) {
            console.error("Could not load webhook configuration", e);
        }
        return configsByCategory;
    }

    function renderWebhookConfigs(configsByCategory) {
        const container = document.getElementById('webhook-configs-container');
        container.innerHTML = '';

        WEBHOOK_CATEGORIES.forEach(({ category, label, description }) => {
            const existing = configsByCategory[category] || {};
            const isConfigured = !!existing.webhook_url;
            const isEnabled = isConfigured && existing.enabled !== false;

            let statusBadge;
            if (!isConfigured) {
                statusBadge = '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-slate-100 text-slate-500">Not Configured</span>';
            } else if (isEnabled) {
                statusBadge = '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-green-100 text-green-700">● Active</span>';
            } else {
                statusBadge = '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-gray-200 text-gray-600">● Deactivated</span>';
            }

            const card = document.createElement('div');
            card.className = 'card';
            card.innerHTML = `
                <div class="flex justify-between items-start mb-1">
                    <h2 class="text-md font-bold text-slate-700 tracking-tight">${esc(label)}</h2>
                    ${statusBadge}
                </div>
                <p class="text-xs text-slate-500 mb-3">${esc(description)}</p>
                <div class="webhook-form" data-category="${esc(category)}">
                    <div class="mb-2">
                        <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Webhook URL</label>
                        <input type="text" data-field="webhook_url" value="${esc(existing.webhook_url || '')}"
                               class="w-full p-2 border border-gray-300 rounded-md text-sm" placeholder="https://your-system.example.com/webhook">
                    </div>
                    <div class="mb-2">
                        <label class="block text-xs font-bold text-slate-500 uppercase mb-1">
                            Secret ${existing.secret_configured ? '<span class="text-green-600">(configured ✓ - leave blank to keep it)</span>' : '<span class="text-amber-600">(not configured)</span>'}
                        </label>
                        <input type="password" data-field="secret" value="" autocomplete="new-password"
                               class="w-full p-2 border border-gray-300 rounded-md text-sm" placeholder="${existing.secret_configured ? 'Leave blank to keep current secret' : 'Required to enable this webhook'}">
                    </div>
                </div>
                <div class="flex justify-end gap-2">
                    ${isConfigured ? `<button class="px-4 py-2 rounded-md text-sm font-medium border ${isEnabled ? 'border-red-200 text-red-600 hover:bg-red-50' : 'border-green-200 text-green-700 hover:bg-green-50'}" data-webhook-action="toggle">${isEnabled ? 'Deactivate' : 'Activate'}</button>` : ''}
                    <button class="primary-bg text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-opacity-90" data-webhook-action="save">Save</button>
                </div>
            `;
            const toggleBtn = card.querySelector('[data-webhook-action="toggle"]');
            if (toggleBtn) toggleBtn.addEventListener('click', () => toggleWebhookEnabled(category, isEnabled));
            card.querySelector('[data-webhook-action="save"]').addEventListener('click', () => saveWebhookConfig(category, isEnabled));
            container.appendChild(card);
        });
    }

    async function saveWebhookConfig(category, currentlyEnabled) {
        const formDiv = document.querySelector(`.webhook-form[data-category="${category}"]`);
        const webhookUrl = formDiv.querySelector('input[data-field="webhook_url"]').value.trim();
        const secret = formDiv.querySelector('input[data-field="secret"]').value;

        if (!webhookUrl) return alert("Enter a webhook URL first.");

        // Save only edits URL/secret -- it preserves whatever active/deactivated state
        // is already in effect. Use the Activate/Deactivate button to change that.
        await submitWebhookConfig(category, webhookUrl, secret, currentlyEnabled, category + " webhook saved.");
    }

    async function toggleWebhookEnabled(category, currentlyEnabled) {
        const formDiv = document.querySelector(`.webhook-form[data-category="${category}"]`);
        const webhookUrl = formDiv.querySelector('input[data-field="webhook_url"]').value.trim();
        const nextEnabled = !currentlyEnabled;

        if (!confirm(`${nextEnabled ? 'Activate' : 'Deactivate'} the ${category} webhook?`)) return;

        await submitWebhookConfig(category, webhookUrl, '', nextEnabled,
            `${category} webhook ${nextEnabled ? 'activated' : 'deactivated'}.`);
    }

    async function submitWebhookConfig(category, webhookUrl, secret, enabled, successMessage) {
        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({
                    "_func": "set_webhook_config",
                    "fiduciary_id": FIDUCIARY_ID,
                    "category": category,
                    "webhook_url": webhookUrl,
                    "secret": secret || undefined,
                    "enabled": enabled
                })
            });
            if (response.ok) {
                alert(successMessage);
                const configsByCategory = await loadWebhookConfigs();
                renderWebhookConfigs(configsByCategory);
            } else {
                const err = await response.json().catch(() => ({}));
                alert("Failed to save webhook: " + (err.message || response.status));
            }
        } catch (e) {
            alert("Network error while saving webhook.");
        }
    }

    // CW-08: per-processor webhook endpoints.
    async function loadApps() {
        try {
            const response = await fetch('/api/v1/admin/app', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_apps", "fiduciary_id": FIDUCIARY_ID })
            });
            const rows = await response.json();
            return Array.isArray(rows) ? rows.filter(a => a.status === 'ACTIVE') : [];
        } catch (e) {
            console.error("Could not load processors", e);
            return [];
        }
    }

    async function loadProcessorWebhookConfigs() {
        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "list_processor_webhook_configs", "fiduciary_id": FIDUCIARY_ID })
            });
            const rows = await response.json();
            return Array.isArray(rows) ? rows : [];
        } catch (e) {
            console.error("Could not load processor webhooks", e);
            return [];
        }
    }

    function renderProcessorWebhooks(apps, configs) {
        const container = document.getElementById('processor-webhooks-container');
        if (!container) return;
        if (!apps.length) {
            container.innerHTML = '<div class="card text-center text-gray-500">No active processors (apps) for this organisation.</div>';
            return;
        }
        const byKey = {};
        configs.forEach(c => { byKey[c.app_id + ':' + c.category] = c; });
        container.innerHTML = apps.map(app => `
            <div class="card">
                <h4 class="text-sm font-bold text-slate-700 mb-2">${esc(app.name)} <span class="text-xs font-mono text-slate-400">${esc(app.app_id)}</span></h4>
                ${WEBHOOK_CATEGORIES.map(({ category, label }) => {
                    const c = byKey[app.app_id + ':' + category] || {};
                    return `
                    <div class="processor-webhook-form grid grid-cols-1 md:grid-cols-5 gap-2 items-end mb-2" data-app="${esc(app.app_id)}" data-category="${esc(category)}">
                        <label class="text-xs font-bold text-slate-500 uppercase md:col-span-1">${esc(label)}</label>
                        <input type="text" data-field="webhook_url" value="${esc(c.webhook_url || '')}" placeholder="https://processor.example.com/webhook"
                               class="md:col-span-2 p-2 border border-gray-300 rounded-md text-sm">
                        <input type="password" data-field="secret" autocomplete="new-password" placeholder="${c.webhook_url ? 'Leave blank to keep secret' : 'Shared secret'}"
                               class="p-2 border border-gray-300 rounded-md text-sm">
                        <button class="primary-bg text-white px-3 py-2 rounded-md text-sm font-medium" data-action="save-processor-webhook">Save</button>
                    </div>`;
                }).join('')}
            </div>`).join('');
        // P12-08: no inline onclick; app/category come from the row's data-* attributes.
        container.querySelectorAll('button[data-action="save-processor-webhook"]').forEach((btn) => {
            const row = btn.closest('.processor-webhook-form');
            btn.addEventListener('click', () => saveProcessorWebhook(row.getAttribute('data-app'), row.getAttribute('data-category')));
        });
    }

    async function saveProcessorWebhook(appId, category) {
        const form = document.querySelector(`.processor-webhook-form[data-app="${CSS.escape(appId)}"][data-category="${CSS.escape(category)}"]`);
        const webhookUrl = form.querySelector('input[data-field="webhook_url"]').value.trim();
        const secret = form.querySelector('input[data-field="secret"]').value;
        if (!webhookUrl) return alert("Enter a webhook URL first.");
        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({
                    "_func": "set_processor_webhook_config", "fiduciary_id": FIDUCIARY_ID, "app_id": appId,
                    "category": category, "webhook_url": webhookUrl, "secret": secret || undefined, "enabled": true
                })
            });
            if (response.ok) {
                alert("Processor webhook saved.");
            } else {
                const err = await response.json().catch(() => ({}));
                alert("Failed to save processor webhook: " + (err.message || response.status));
            }
        } catch (e) {
            alert("Network error while saving processor webhook.");
        }
    }
    window.saveProcessorWebhook = saveProcessorWebhook;

    async function loadRightsAppConfig() {
        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({ "_func": "get_rights_app_config", "fiduciary_id": FIDUCIARY_ID })
            });
            if (!response.ok) throw new Error(response.status);
            return await response.json();
        } catch (e) {
            console.error("Could not load Rights Management App configuration", e);
            return { otp_mode: 'DUMMY_OTP', otp_message_template: '', pca_qr_enabled: true };
        }
    }

    function renderRightsAppConfig(config, otpWebhookConfig) {
        const container = document.getElementById('rights-app-config-container');
        const mode = config.otp_mode || 'DUMMY_OTP';
        const existing = otpWebhookConfig || {};
        container.innerHTML = `
            <div class="mb-4">
                <label class="block text-xs font-bold text-slate-500 uppercase mb-1">OTP Delivery Mode</label>
                <select id="rights-otp-mode" class="w-full p-2 border border-gray-300 rounded-md text-sm">
                    <option value="DUMMY_OTP" ${mode === 'DUMMY_OTP' ? 'selected' : ''}>Dummy OTP (always 1234 -- demo/evaluation)</option>
                    <option value="EMAIL_OTP" ${mode === 'EMAIL_OTP' ? 'selected' : ''}>Email OTP</option>
                    <option value="MOBILE_OTP" ${mode === 'MOBILE_OTP' ? 'selected' : ''}>Mobile OTP</option>
                </select>
            </div>
            <div id="rights-otp-webhook-fields" class="${mode === 'DUMMY_OTP' ? 'hidden' : ''} space-y-3 mb-4 pl-3 border-l-2 border-slate-100">
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-1">OTP Delivery Webhook URL</label>
                    <input type="text" id="rights-otp-webhook-url" value="${esc(existing.webhook_url || '')}"
                           class="w-full p-2 border border-gray-300 rounded-md text-sm" placeholder="https://your-system.example.com/otp-webhook">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-1">
                        Secret ${existing.secret_configured ? '<span class="text-green-600">(configured &#10003; - leave blank to keep it)</span>' : '<span class="text-amber-600">(not configured)</span>'}
                    </label>
                    <input type="password" id="rights-otp-webhook-secret" value="" autocomplete="new-password"
                           class="w-full p-2 border border-gray-300 rounded-md text-sm" placeholder="${existing.secret_configured ? 'Leave blank to keep current secret' : 'Required to enable OTP delivery'}">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Message Template</label>
                    <textarea id="rights-otp-message" rows="2" class="w-full p-2 border border-gray-300 rounded-md text-sm" placeholder="Your verification code is {{otp}}">${esc(config.otp_message_template || '')}</textarea>
                    <p class="text-xs text-slate-400 mt-1">Use <code>{{otp}}</code> as a placeholder for the generated code. Your webhook receiver is responsible for actually sending the email/SMS.</p>
                </div>
            </div>
            <label class="flex items-center gap-2 mb-4 text-sm text-slate-600">
                <input type="checkbox" id="rights-pca-qr-enabled" ${config.pca_qr_enabled !== false ? 'checked' : ''}>
                Enable PCA QR Code in the Privacy Dashboard
            </label>
            <div class="flex justify-end">
                <button class="primary-bg text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-opacity-90" id="rights-app-config-save-btn">Save</button>
            </div>
        `;
        // P12-08: listeners attached here instead of inline onchange/onclick attributes.
        document.getElementById('rights-otp-mode').addEventListener('change', () => onRightsOtpModeChange());
        document.getElementById('rights-app-config-save-btn').addEventListener('click', () => saveRightsAppConfig());
    }

    function onRightsOtpModeChange() {
        const mode = document.getElementById('rights-otp-mode').value;
        document.getElementById('rights-otp-webhook-fields').classList.toggle('hidden', mode === 'DUMMY_OTP');
    }

    async function saveRightsAppConfig() {
        const mode = document.getElementById('rights-otp-mode').value;
        const pcaQrEnabled = document.getElementById('rights-pca-qr-enabled').checked;
        const messageTemplate = document.getElementById('rights-otp-message').value;

        if (mode !== 'DUMMY_OTP') {
            const webhookUrl = document.getElementById('rights-otp-webhook-url').value.trim();
            const secret = document.getElementById('rights-otp-webhook-secret').value;
            if (!webhookUrl) return alert("Enter an OTP delivery webhook URL first.");
            try {
                const webhookResponse = await fetch(API_URL_NOTIFICATION, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({
                        "_func": "set_webhook_config",
                        "fiduciary_id": FIDUCIARY_ID,
                        "category": "OTP",
                        "webhook_url": webhookUrl,
                        "secret": secret || undefined,
                        "enabled": true
                    })
                });
                if (!webhookResponse.ok) {
                    const err = await webhookResponse.json().catch(() => ({}));
                    alert("Failed to save OTP webhook: " + (err.message || webhookResponse.status));
                    return;
                }
            } catch (e) {
                alert("Network error while saving OTP webhook.");
                return;
            }
        }

        try {
            const response = await fetch(API_URL_NOTIFICATION, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify({
                    "_func": "set_rights_app_config",
                    "fiduciary_id": FIDUCIARY_ID,
                    "otp_mode": mode,
                    "otp_message_template": messageTemplate || undefined,
                    "pca_qr_enabled": pcaQrEnabled
                })
            });
            if (response.ok) {
                alert("Rights Management App settings saved.");
                const [config, webhookConfigs] = await Promise.all([loadRightsAppConfig(), loadWebhookConfigs()]);
                renderRightsAppConfig(config, webhookConfigs['OTP']);
            } else {
                const err = await response.json().catch(() => ({}));
                alert("Failed to save settings: " + (err.message || response.status));
            }
        } catch (e) {
            alert("Network error while saving Rights Management App settings.");
        }
    }

    async function init() {
        const [languages, existingMessages, webhookConfigs, rightsAppConfig] = await Promise.all([
            loadSupportedLanguages(), loadExistingMessages(), loadWebhookConfigs(), loadRightsAppConfig()
        ]);
        SUPPORTED_LANGUAGES = languagesFor(languages, existingMessages);
        renderSettingsForm(SUPPORTED_LANGUAGES, existingMessages);
        renderBreachTypes(SUPPORTED_LANGUAGES, existingMessages);
        renderAddLanguage();
        renderWebhookConfigs(webhookConfigs);
        renderProcessorWebhooks(...(await Promise.all([loadApps(), loadProcessorWebhookConfigs()])));
        renderRightsAppConfig(rightsAppConfig, webhookConfigs['OTP']);
    }

    document.getElementById('menu-toggle').addEventListener('click', toggleMenu);
    document.getElementById('sidebar-backdrop').addEventListener('click', toggleMenu);

    init();

    window.saveMessage = saveMessage;
    window.addNotificationLanguage = addNotificationLanguage;
    window.addBreachType = addBreachType;
    window.saveWebhookConfig = saveWebhookConfig;
    window.toggleWebhookEnabled = toggleWebhookEnabled;
    window.onRightsOtpModeChange = onRightsOtpModeChange;
    window.saveRightsAppConfig = saveRightsAppConfig;
    window.handleLogout = () => { localStorage.clear(); window.location.href = "../index.html"; };
