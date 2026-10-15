// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    document.getElementById('login-form').addEventListener('submit', (e) => handleLogin(e));
})();

/**
 * Function to handle the admin login process via API authentication using the Fetch API.
 */
async function handleLogin(event) {
    const API_LOGIN_URL = 'api/v1/admin/operator';
    const ADMIN_DASHBOARD_URL = 'console/admin/dashboard.html';
    const DPO_DASHBOARD_URL = 'console/dpo/dashboard.html';

    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const messageArea = document.getElementById('login-message');
    const mfaField = document.getElementById('mfa-field');
    const mfaCode = document.getElementById('mfa-code');

    // Reset UI
    messageArea.textContent = '';
    messageArea.classList.add('hidden');
    messageArea.classList.remove('text-red-500', 'text-teal-600', 'text-blue-500');

    // Complexity Validation
    if (password.length < 12) {
        messageArea.textContent = "Error: Password must be at least 12 characters long.";
        messageArea.classList.remove('hidden');
        messageArea.classList.add('text-red-500');
        return;
    }

    messageArea.textContent = "Verifying session with Consent Management System...";
    messageArea.classList.remove('hidden');
    messageArea.classList.add('text-blue-500');

    // Step two: complete MFA with the challenge token from the first response.
    const pendingToken = localStorage.getItem('pendingAuthToken');
    if (pendingToken && mfaCode.value.trim()) {
        const code = mfaCode.value.trim();
        if (code.length !== 6 || !/^\d{6}$/.test(code)) {
            messageArea.textContent = "Enter the 6-digit code from your authenticator app.";
            messageArea.classList.replace('text-blue-500', 'text-teal-600');
            mfaCode.focus();
            return;
        }
        const verifyResponse = await fetch(API_LOGIN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + pendingToken },
            body: JSON.stringify({ _func: "verify_mfa", code: code })
        });
        const verifyData = await verifyResponse.json();
        localStorage.removeItem('pendingAuthToken');
        if (verifyResponse.ok && verifyData.success === true && verifyData.token) {
            localStorage.setItem('authToken', verifyData.token);
            localStorage.setItem('username', localStorage.getItem('pendingUsername') || '');
            localStorage.setItem('role', verifyData.role || localStorage.getItem('pendingRole') || '');
            localStorage.setItem('fiduciary_id', localStorage.getItem('pendingFiduciaryId') || '');
            localStorage.removeItem('pendingUsername');
            localStorage.removeItem('pendingRole');
            localStorage.removeItem('pendingFiduciaryId');
            messageArea.textContent = "MFA verified. Redirecting to vault...";
            messageArea.classList.replace('text-blue-500', 'text-teal-600');
            setTimeout(() => {
                window.location.href = (localStorage.getItem('role') === 'ADMIN') ? ADMIN_DASHBOARD_URL : DPO_DASHBOARD_URL;
            }, 800);
        } else {
            messageArea.textContent = verifyData.message || "Invalid authenticator code. Please try again.";
            messageArea.classList.replace('text-blue-500', 'text-red-500');
            mfaCode.value = '';
            mfaCode.focus();
        }
        return;
    }

    try {
        const payload = { _func: "login", identifier: email, password: password };

        const response = await fetch(API_LOGIN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const responseData = await response.json();

        if (response.ok && responseData.success === true && responseData.mfa_required) {
            // Step two: MFA is enabled on this account. Persist the challenge
            // token, show the code input, and wait for a second submit.
            localStorage.setItem('pendingAuthToken', responseData.token);
            localStorage.setItem('pendingUsername', responseData.username);
            localStorage.setItem('pendingRole', responseData.role);
            localStorage.setItem('pendingFiduciaryId', responseData.fiduciary_id);
            messageArea.textContent = "Enter the 6-digit code from your authenticator app.";
            messageArea.classList.replace('text-blue-500', 'text-teal-600');
            mfaField.classList.remove('hidden');
            mfaCode.focus();
            return;
        }

        if (response.ok && responseData.success === true) {
            // Persist context for management console
            localStorage.setItem('authToken', responseData.token);
            localStorage.setItem('username', responseData.username);
            localStorage.setItem('role', responseData.role);
            localStorage.setItem('fiduciary_id', responseData.fiduciary_id);
            localStorage.setItem('fiduciary_name', responseData.fiduciary_name);

            messageArea.textContent = "Login successful. Redirecting to vault...";
            messageArea.classList.replace('text-blue-500', 'text-teal-600');

            setTimeout(() => {
                if(responseData.role === 'ADMIN'){
                    window.location.href = ADMIN_DASHBOARD_URL;
                } else {
                    window.location.href = DPO_DASHBOARD_URL;
                }
            }, 800);

        } else {
            const errorText = responseData.message || "Invalid credentials. Please verify your login ID and password.";
            messageArea.textContent = errorText;
            messageArea.classList.replace('text-blue-500', 'text-red-500');
        }

    } catch (error) {
        messageArea.textContent = 'Network Error: Cannot reach the Consent Management System.';
        messageArea.classList.replace('text-blue-500', 'text-red-500');
        console.error('Connection error:', error);
    }
}
