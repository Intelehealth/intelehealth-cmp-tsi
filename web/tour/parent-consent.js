// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        transitionToOtp: () => transitionToOtp(),
        verifyOtpAndLoadPolicy: () => verifyOtpAndLoadPolicy(),
        switchPhase: (el) => switchPhase(el.getAttribute('data-arg')),
        executeRegistrySync: () => executeRegistrySync(),
        goToLearnerDashboard: () => { window.location.href = 'user-dashboard.html'; },
        closeMsgModal: () => { document.getElementById('msg-modal').style.display = 'none'; },
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
})();

    // --- Configuration ---
    const API_BASE_URL = (typeof config !== 'undefined' && config.tsi_dpdp_cms_apibaseurl)
        ? config.tsi_dpdp_cms_apibaseurl
        : window.location.origin;
    const API_BASE = `${API_BASE_URL}/api/v1/client/consent`;
    const POLICY_API = `${API_BASE_URL}/api/v1/client/policy`;

    // Credentials initialized to null, populated via modal
    let X_API_KEY = null;
    let X_API_SECRET = null;
    let POLICY_ID = null;

    // CF-02/SEC-11: policy contents come from the API and are caller-controllable;
    // escape every interpolated value before it reaches innerHTML.
    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
    }

    let currentPolicy = null;
    let verificationLogId = null;
    let learnerChoices = {};

    // UI Helpers
    function switchPhase(phaseId) {
        document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
        document.getElementById('phase-' + phaseId).classList.remove('hidden');

        // Update Indicators
        const step = phaseId === 'identity' ? 1 : (phaseId === 'otp' ? 2 : 3);
        for(let i=1; i<=3; i++) {
            const el = document.getElementById(`step-${i}-indicator`);
            el.className = `stepper-circle ${i <= step ? 'stepper-active' : 'stepper-inactive'}`;
        }
    }

    function showModal(title, body) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-body').textContent = body;
        document.getElementById('msg-modal').style.display = 'flex';
    }

    // Phase 1 -> 2
    function transitionToOtp() {
        const name = document.getElementById('student-name').value.trim();
        const email = document.getElementById('student-email').value.trim();
        const pMobile = document.getElementById('guardian-mobile').value.trim();

        if(!name || !email || !pMobile) return alert("Please complete all learner and guardian fields.");

        // Simulation: Cache details
        localStorage.setItem('temp_learner_email', email);
        localStorage.setItem('temp_learner_name', name);
        localStorage.setItem('temp_guardian_name', document.getElementById('guardian-name').value);
        localStorage.setItem('temp_guardian_mobile', pMobile);

        switchPhase('otp');
    }

    // Phase 2 -> 3
    async function verifyOtpAndLoadPolicy() {
        const otp = document.getElementById('otp-input').value;
        if(otp !== '123456') return alert("Invalid Verification Code. (Try 123456)");

        switchPhase('consent');
        await loadVidyaPolicy();
    }

    async function loadVidyaPolicy() {
        try {
            const res = await fetch(POLICY_API, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-Key': X_API_KEY, 'X-API-Secret': X_API_SECRET },
                body: JSON.stringify({ "_func": "get_policy", "policy_id": POLICY_ID })
            });
            const data = await res.json();
            const content = typeof data.policy_content === 'string' ? JSON.parse(data.policy_content) : data.policy_content;
            currentPolicy = content.en; // Defaulting to English

            renderPurposes(currentPolicy.data_processing_purposes);
        } catch (e) {
            showModal("Registry Error", "Could not fetch the learner policy. Check connectivity and credentials.");
        }
    }

    function renderPurposes(purposes) {
        const container = document.getElementById('policy-content');
        container.innerHTML = '';
        learnerChoices = {}; // raw purpose id -> checkbox element (P6-08)

        purposes.forEach(p => {
            const requiresVPC = p.requires_parental_consent === true;
            const div = document.createElement('div');
            div.className = "p-4 bg-slate-50 rounded-2xl border border-slate-100 transition-all hover:bg-white hover:border-amber-200";

            div.innerHTML = `
                <div class="flex justify-between items-start mb-2">
                    <div class="max-w-[85%]">
                        <p class="font-bold text-slate-800 text-sm">${esc(p.name)}</p>
                        <p class="text-[10px] text-slate-500 mt-1">${esc(p.description)}</p>
                    </div>
                    <input type="checkbox" class="purpose-check w-5 h-5 rounded border-slate-300 text-teal-600 focus:ring-teal-500"
                        ${p.is_mandatory_for_service ? 'checked disabled' : 'checked'}>
                </div>
                <div class="flex gap-2 mt-3">
                    <span class="text-[8px] font-black uppercase bg-white border px-1.5 py-0.5 rounded text-slate-400">Retention: ${esc(p.retention_duration_value)} ${esc(p.retention_duration_unit)}</span>
                    ${requiresVPC ? '<span class="text-[8px] font-black uppercase bg-amber-50 text-amber-600 border border-amber-100 px-1.5 py-0.5 rounded">VPC REQUIRED</span>' : ''}
                </div>
            `;
            container.appendChild(div);
            // P6-08: keep the raw id in the map, never in a getElementById string
            // built from escaped markup — a purpose id containing an entity
            // character used to make the lookup return null.
            learnerChoices[p.id] = div.querySelector('.purpose-check');
        });
    }

    async function executeRegistrySync() {
        const btn = document.getElementById('final-consent-btn');
        btn.disabled = true;
        btn.textContent = "Updating Registry...";

        try {
            const studentEmail = localStorage.getItem('temp_learner_email');
            const guardianName = localStorage.getItem('temp_guardian_name');
            const guardianMobile = localStorage.getItem('temp_guardian_mobile');
            const anonymousId = localStorage.getItem('tsi_dpdp_cms_anon_id') || `anon_${Date.now()}`;
            const timestamp = new Date().toISOString();

            // 1. Record Parental Verification Artifact
            const vpcRes = await fetch(API_BASE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-Key': X_API_KEY, 'X-API-Secret': X_API_SECRET },
                body: JSON.stringify({
                    "_func": "record_parent_consent",
                    "child_principal_id": studentEmail,
                    "guardian_principal_id": guardianMobile,
                    "verification_mechanism": "INTERNAL_OTP",
                    "provider_name": "VIDYA_AUTH_ENGINE",
                    "verification_ref_id": "otp_tx_" + Math.random().toString(36).substr(2, 9),
                    "proof_metadata": { "guardian_name": guardianName, "timestamp": timestamp }
                })
            });
            const vpcData = await vpcRes.json();
            verificationLogId = vpcData.verification_log_id;

            // 2. Link Identity (Consolidation with MINOR metadata)
            await fetch(API_BASE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-Key': X_API_KEY, 'X-API-Secret': X_API_SECRET },
                body: JSON.stringify({
                    "_func": "link_user",
                    "anonymous_user_id": anonymousId,
                    "authenticated_user_id": studentEmail,
                    "age_category": "MINOR",
                    "guardian_id": guardianMobile,
                    "verification_status": "VERIFIED"
                })
            });

            // 3. Record Actual Consent (Atomic Link to Verification Log)
            const finalChoices = [];
            currentPolicy.data_processing_purposes.forEach(p => {
                const checkbox = learnerChoices[p.id];
                const checked = checkbox ? checkbox.checked : false; // P6-08: read via the map, never an escaped id
                finalChoices.push({
                    "data_point_id": p.id,
                    "consent_granted": checked,
                    "purpose_agreed_to": p.name,
                    "timestamp_updated": timestamp
                });
            });

            await fetch(API_BASE, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-Key': X_API_KEY, 'X-API-Secret': X_API_SECRET },
                body: JSON.stringify({
                    "_func": "record_consent",
                    "user_id": studentEmail,
                    "policy_id": POLICY_ID,
                    "verification_log_id": verificationLogId,
                    "data_point_consents": finalChoices,
                    "user_agent": navigator.userAgent
                })
            });

            localStorage.setItem('dp_user_id', studentEmail);
            switchPhase('success');

        } catch (e) {
            console.error(e);
            showModal("Sync Failure", "The registry could not verify the parental artifact. Please try again.");
            btn.disabled = false;
            btn.textContent = "Retry Authorization";
        }
    }

    // --- App Bootstrap ---
    document.addEventListener('DOMContentLoaded', () => {
        // Always generate a fresh anonymous session tracker on refresh if not present
        if(!localStorage.getItem('tsi_dpdp_cms_anon_id')) {
            localStorage.setItem('tsi_dpdp_cms_anon_id', 'anon_vidya_' + Math.random().toString(36).substr(2, 9));
        }

        const storedKey = localStorage.getItem('x_api_key');
        const storedSecret = localStorage.getItem('x_api_secret');
        const storedPolicy = localStorage.getItem('policy_id');

        // FORCE DISPLAY: Always show the authorization/credentials modal on page load or refresh
        document.getElementById('credentials-modal').style.display = 'flex';

        // CONVENIENCE: Pre-fill fields if they exist in storage so the user just needs to click "Initialize"
        if (storedKey) {
            document.getElementById('api-key-input').value = storedKey;
            X_API_KEY = storedKey;
        }
        if (storedSecret) {
            document.getElementById('api-secret-input').value = storedSecret;
            X_API_SECRET = storedSecret;
        }
        if (storedPolicy) {
            document.getElementById('policy-id-input').value = storedPolicy;
            POLICY_ID = storedPolicy;
        }
    });

    document.getElementById('save-credentials-btn').onclick = () => {
        const key = document.getElementById('api-key-input').value.trim();
        const secret = document.getElementById('api-secret-input').value.trim();
        const pId = document.getElementById('policy-id-input').value.trim();

        if (key && secret && pId) {
            localStorage.setItem('x_api_key', key);
            localStorage.setItem('x_api_secret', secret);
            localStorage.setItem('policy_id', pId);

            X_API_KEY = key;
            X_API_SECRET = secret;
            POLICY_ID = pId;

            document.getElementById('credentials-modal').style.display = 'none';
        } else {
            alert("All configuration fields are required to start the tour.");
        }
    };
