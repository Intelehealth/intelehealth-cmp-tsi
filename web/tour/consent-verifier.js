// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        clearLog: () => { document.getElementById('log-output').innerHTML = ''; },
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
})();

    // CF-02/SEC-11: every value drawn from the API or user input is escaped
    // before it reaches innerHTML; no caller-controlled string is trusted.
    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    // --- Configuration ---
    const API_BASE_URL = (typeof config !== 'undefined' && config.tsi_dpdp_cms_apibaseurl)
        ? config.tsi_dpdp_cms_apibaseurl
        : window.location.origin;
    const API_VALIDATE_ENDPOINT = `${API_BASE_URL}/api/v1/client/consent`;

    // --DOM elements ---
    const apiKeyInput = document.getElementById('api-key');
    const apiSecretInput = document.getElementById('api-secret');
    const userIdInput = document.getElementById('user-id');
    const purposeIdSelect = document.getElementById('purpose-id');
    const processButton = document.getElementById('process-data-btn');
    const logOutput = document.getElementById('log-output');

    // --- Utility Functions ---

    function logMessage(message, type = 'info') {
        const entry = document.createElement('div');
        entry.className = 'log-entry';

        let colorClass = 'log-info';
        if (type === 'error') colorClass = 'log-error';
        if (type === 'success') colorClass = 'log-success';

        entry.innerHTML = `
            <span class="log-time">${esc(new Date().toLocaleTimeString())}</span>
            <span class="${colorClass}">${esc(message)}</span>
        `;
        logOutput.prepend(entry);
    }

    // --- Core Validation Logic ---

    async function checkConsentAndProcess() {
        const userId = userIdInput.value.trim();
        const requiredPurpose = purposeIdSelect.value.trim();
        const apikey = apiKeyInput.value.trim();
        const apisecret = apiSecretInput.value.trim();

        if (!userId) {
            logMessage("ERROR: Data Principal ID is required.", 'error');
            return;
        }
        if (!requiredPurpose) {
            logMessage("ERROR: Purpose ID is required for validation.", 'error');
            return;
        }

        logMessage(`INITIATING: Validating [${requiredPurpose}] for [${userId}]...`);
        processButton.disabled = true;

        try {
            const validationPayload = {
                "_func": "validate_consent",
                "user_id": userId,
                "required_purpose_id": requiredPurpose
            };

            const response = await fetch(API_VALIDATE_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': apikey,
                    'X-API-Secret': apisecret
                },
                body: JSON.stringify(validationPayload)
            });

            if (response.status === 200) {
                const result = await response.json();

                // CMS returns { valid, status: "VALID" | "INVALID", required_purpose_id }
                const granted = (result.valid === true) || (result.status === 'VALID');
                const denied  = (result.valid === false) || (result.status === 'INVALID');

                if (granted) {
                    logMessage("VALIDATION SUCCESS: Consent is active and verifiable.", 'success');
                    await simulateDataProcessing(userId, requiredPurpose);
                } else if (denied) {
                    logMessage("ACCESS DENIED: Data Principal has revoked/denied consent.", 'error');
                    logMessage("COMPLIANCE: Processing halted to respect privacy preference.", 'info');
                } else {
                    logMessage(`FAILURE: CMS returned insufficient status. ${result.message || 'Unknown error'}`, 'error');
                }

            } else if (response.status === 401 || response.status === 403) {
                logMessage("AUTH ERROR: Invalid API Credentials. Check Key/Secret.", 'error');
            } else {
                logMessage(`SERVER ERROR: Registry returned status ${response.status}`, 'error');
            }

        } catch (error) {
            logMessage(`NETWORK ERROR: Registry endpoint unreachable.`, 'error');
            console.error("Validation API error:", error);
        } finally {
            processButton.disabled = false;
        }
    }

    function simulateDataProcessing(userId, purpose) {
        logMessage(`PROCESSING: Handling data for ${userId}...`, 'info');
        return new Promise(resolve => {
            setTimeout(() => {
                logMessage("COMPLETE: Data processed strictly for consented purpose.", 'success');
                resolve();
            }, 1200);
        });
    }

    // --- Event Listener ---
    processButton.addEventListener('click', checkConsentAndProcess);
    document.getElementById('log-seed-time').textContent = new Date().toLocaleTimeString();
