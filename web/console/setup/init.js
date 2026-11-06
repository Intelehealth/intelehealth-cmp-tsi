        document.addEventListener('DOMContentLoaded', () => {
            const API_SETUP_URL = `${window.location.origin}/api/v1/bootstrap/setup`;
            const LOGIN_PAGE_URL = '../index.html';

            const form = document.getElementById('setup-form');
            const messageArea = document.getElementById('setup-message');
            const loginLink = document.getElementById('login-link');
            const setupBtn = document.getElementById('setup-btn');

            const emailInput = document.getElementById('email');
            const nameInput = document.getElementById('name');
            const passwordInput = document.getElementById('password');
            const passwordConfirmInput = document.getElementById('password-confirm');
            const bootstrapTokenInput = document.getElementById('bootstrap-token');

            function displayMessage(text, isError) {
                messageArea.textContent = text;
                messageArea.classList.remove('hidden', 'text-red-500', 'text-green-500');
                messageArea.classList.add(isError ? 'text-red-500' : 'text-green-500');
            }

            form.addEventListener('submit', async function(event) {
                event.preventDefault();

                // Reset state
                messageArea.classList.add('hidden');
                setupBtn.disabled = true;
                setupBtn.textContent = 'Processing Setup...';
                loginLink.style.display = 'none';

                const email = emailInput.value.trim();
                const name = nameInput.value.trim();
                const password = passwordInput.value;
                const passwordConfirm = passwordConfirmInput.value;
                const bootstrapToken = bootstrapTokenInput.value.trim();

                // Client-side Validation Checks
                if (!bootstrapToken) {
                    displayMessage("Error: Bootstrap token is required.", true);
                    setupBtn.disabled = false;
                    setupBtn.textContent = 'Finalize Setup & Create Admin';
                    return;
                }
                if (password.length < 12) {
                    displayMessage("Error: Password must be at least 12 characters long.", true);
                    setupBtn.disabled = false;
                    setupBtn.textContent = 'Finalize Setup & Create Admin';
                    return;
                }
                if (password !== passwordConfirm) {
                    displayMessage("Error: Passwords do not match.", true);
                    setupBtn.disabled = false;
                    setupBtn.textContent = 'Finalize Setup & Create Admin';
                    return;
                }

                try {
                    // 1. Prepare Payload
                    const payload = {
                        "_func": "initial_setup",
                        "email": email,
                        "name": name,
                        "password": password,
                        "bootstrap_token": bootstrapToken
                    };

                    // 2. Perform API Setup Call
                    const response = await fetch(API_SETUP_URL, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    // We must always read the response body to handle API-level errors
                    const responseData = await response.json();

                    if (response.ok && responseData.success === true) {
                        // --- SUCCESS ---
                        displayMessage("Setup complete! Super Administrator account created successfully.", false);
                        setupBtn.textContent = 'Setup Complete';
                        setupBtn.disabled = false;
                        form.style.display = 'none';
                        // Show login link after successful setup
                        loginLink.style.display = 'block';

                    } else {
                        // --- FAILURE ---
                        let errorText = "Setup failed. This usually means the system is already configured.";
                        if (responseData.error && responseData.error.message) {
                            errorText = responseData.error.message;
                        } else if (response.status !== 200) {
                            errorText = `Setup failed (Status: ${response.status}). The server likely rejected the request.`;
                        }

                        displayMessage(errorText, true);
                        setupBtn.textContent = 'Setup Failed - Retry';
                    }

                } catch (error) {
                    // Handle network error
                    displayMessage('Cannot connect to the setup server. Check if the backend is running.', true);
                    setupBtn.textContent = 'Connection Error - Retry';
                } finally {
                    setupBtn.disabled = false;
                }
            });
        });
