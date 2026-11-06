// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        handleLogout: () => handleLogout(),
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

    // --- Configuration ---
    // Assuming API structure based on FiduciaryService and convention
    const API_URL_APPS = '/api/v1/admin/app';
    const API_URL_FIDUCIARIES_LIST = '/api/v1/admin/fiduciary'; // To populate dropdown
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const USER_NAME = localStorage.getItem('username');
    // set user name
    document.getElementById('username').textContent = USER_NAME;

    // --- Global DOM Element Variables ---
    let sidebar, menuToggle, backdrop, appModalOverlay, addAppBtn, closeModalBtn, appForm, tableBody, countSpan, errorMessageP, searchInput;
    let appIdHidden, appNameInput, fiduciarySelect, appEmailInput, appPhoneInput, processingPurposeInput, dpaReferenceInput;

    let FiduciaryList = []; // Cache Fiduciary names for display

    // --- Helper Functions ---

    function toggleMenu() {
        sidebar.classList.toggle('open');
        backdrop.classList.toggle('hidden');
    }

    function showModal(title, isEdit = false) {
        document.getElementById('modal-title').textContent = title;
        appForm.reset();
        appIdHidden.value = '';

        document.getElementById('save-app-btn').textContent = isEdit ? 'Update App' : 'Save App';

        // Ensure inputs are enabled for creation, or potentially disabled/locked for editing sensitive fields
        appNameInput.disabled = false;
        fiduciarySelect.disabled = false;
        appModalOverlay.style.display = 'flex';
    }

    function closeModal() {
        appModalOverlay.style.display = 'none';
    }

    function createStatusBadge(status) {
        let colorClass = '';
        switch (status) {
            case 'ACTIVE': colorClass = 'bg-green-100 text-green-800'; break;
            case 'PENDING': colorClass = 'bg-yellow-100 text-yellow-800'; break;
            case 'INACTIVE':
            case 'REVOKED': colorClass = 'bg-red-100 text-red-800'; break;
            default: colorClass = 'bg-gray-100 text-gray-800';
        }
        return `<span class="px-3 py-1 text-xs font-medium rounded-full ${colorClass}">${esc(status)}</span>`;
    }

    // Function to get Fiduciary Name from ID (for display purposes)
    function getFiduciaryName(id) {
        const fiduciary = FiduciaryList.find(f => f.fiduciary_id === id);
        return fiduciary ? fiduciary.name : 'Unknown Fiduciary';
    }

    function createAppRow(app) {
        const row = document.createElement('tr');
        const showDeactivate = app.status === 'ACTIVE' || app.status === 'PENDING';

        const actionsHtml = `
            ${showDeactivate ?
                `<button class="edit-app-btn text-indigo-600 hover:text-indigo-900 font-medium text-sm mr-2">Edit</button><button class="deactivate-app-btn text-red-600 hover:text-red-900 font-medium text-sm">Deactivate</button>`
                : `<span class="text-gray-500 text-xs">Access Suspended</span>`}
        `;

        row.innerHTML = `
            <td class="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">${esc(app.name || 'N/A')}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${esc(getFiduciaryName(app.fiduciary_id))}</td>
            <td class="px-4 py-3 text-sm text-gray-600">${esc(app.processing_purpose || 'N/A')}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${esc(app.dpa_reference || 'N/A')}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm">${createStatusBadge(app.status)}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm">
                ${actionsHtml}
            </td>
        `;
        const editBtn = row.querySelector('.edit-app-btn');
        if (editBtn) editBtn.addEventListener('click', () => editApp(app.app_id, app.fiduciary_id));
        const deactivateBtn = row.querySelector('.deactivate-app-btn');
        if (deactivateBtn) deactivateBtn.addEventListener('click', () => deactivateApp(app.app_id, app.fiduciary_id));
        return row;
    }

    // --- Core Logic ---

    // 1. Fetch Fiduciaries for Dropdown Population and Name Lookup
    async function fetchFiduciariesForDropdown() {
        try {
            const payload = {
            "_func": "list_fiduciaries",
            "status": "ACTIVE",
            "search": "",
            "page": 1,
            "limit": 50
            };
            const response = await fetch(API_URL_FIDUCIARIES_LIST, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                 // Even if list fails, we want to try loading apps later
                 console.error("Failed to fetch Fiduciaries list for dropdown. Status:", response.status);
                 return [];
            }


            const responseData = await response.json();

            if (responseData.status === 401) {
              alert("Session Expired: " + (responseData.message || "Authentication required."));
              handleLogout();
              return;
            }

            FiduciaryList = responseData; // Assuming backend returns array of Fiduciaries

            fiduciarySelect.innerHTML = '<option value="">-- Select Fiduciary --</option>';
            FiduciaryList.forEach(f => {
                const option = document.createElement('option');
                option.value = f.fiduciary_id;
                option.textContent = f.name;
                fiduciarySelect.appendChild(option);
            });
            return responseData;
        } catch (error) {
            console.error("Error fetching Fiduciaries for dropdown:", error);
            return [];
        }
    }


    // 2. Load Apps List
    async function loadApps(searchTerm = "") {
        tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">Loading Apps...</td></tr>`;
        errorMessageP.classList.add('hidden');

        // Ensure Fiduciary list is loaded first for display names
        if (FiduciaryList.length === 0) {
            const fids = await fetchFiduciariesForDropdown();
            if (fids.length === 0) {
                 tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">
                    No Data Fiduciaries found.
                 </td></tr>`;
                 countSpan.textContent = '0 Total';
                 return;
            }
        }

        try {
            const listPayload = {
                "_func": "list_apps",
                "fiduciary_id": "",
                "search": searchTerm,
                "status": "",
                "page": 1,
                "limit": 50
            };

            const response = await fetch(API_URL_APPS, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${AUTH_TOKEN}`
                },
                body: JSON.stringify(listPayload)
            });

            if (!response.ok) throw new Error(`API returned status ${response.status}`);

            const responseData = await response.json();

            // Assuming responseData structure is: [{...}, {...}]
            if (Array.isArray(responseData)) {
                const apps = responseData;
                tableBody.innerHTML = '';

                if (apps.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">No Apps found matching criteria.</td></tr>`;
                } else {
                    apps.forEach(app => {
                        tableBody.appendChild(createAppRow(app));
                    });
                    countSpan.textContent = `Showing 1 - ${apps.length} of ${apps.length} Total`;
                }
            } else {
                throw new Error(responseData.message || 'API returned unexpected structure.');
            }

        } catch (error) {
            console.error("Error loading apps:", error);
            tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-red-600">
                Error connecting to the CMS API. Ensure the service is running and the token is valid.
            </td></tr>`;
            errorMessageP.classList.remove('hidden');
            countSpan.textContent = '0 Total';
        }
    }

    // 3. Fetch Single App Details
    async function fetchAppDetails(appId, fiduciaryId) {
        try {
            const payload = {
                "_func": "get_app",
                "app_id": appId,
                "fiduciary_id": fiduciaryId // Include Fiduciary ID in the payload
            };

            const response = await fetch(API_URL_APPS, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error(`Failed to fetch details for ${appId}. Status: ${response.status}`);

            const responseData = await response.json();

            if (responseData.name) {
                return responseData;
            } else {
                throw new Error(responseData.message || 'App details not found.');
            }
        } catch (error) {
            console.error("Error fetching App details:", error);
            alert(`Failed to load details for editing: ${error.message}`);
            return null;
        }
    }

    // 4. Handle Edit
    async function editApp(appId, fiduciaryId) {
        showModal('Edit App', true);
        const app = await fetchAppDetails(appId, fiduciaryId);
        console.log(app);
        if (app) {
            appIdHidden.value = app.app_id;
            appNameInput.value = app.name || '';
            fiduciarySelect.value = app.fiduciary_id || '';
            appEmailInput.value = app.email || '';
            appPhoneInput.value = app.phone || '';
            processingPurposeInput.value = app.processing_purposes || '';
            dpaReferenceInput.value = app.dpa_reference || '';
            appStatusSelect.value = app.status || 'ACTIVE';

            // Lock fields that should not be changed easily
            appNameInput.disabled = true;
            fiduciarySelect.disabled = true;
        } else {
            closeModal();
        }
    }

    // 5. Handle Deactivate
    async function deactivateApp(appId, fiduciaryId) {
        if (confirm(`Are you sure you want to DEACTIVATE App ID ${appId}? This will suspend all data processing for this entity.`)) {
            try {
                const payload = { "_func": "delete_app", "app_id": appId, "fiduciary_id": fiduciaryId};

                const response = await fetch(API_URL_APPS, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    alert(`App ID ${appId} successfully deactivated.`);
                    loadApps();
                } else {
                    const responseData = await response.json();
                    const errorMsg = responseData.message || responseData.error.message || `Status: ${response.status}`;
                    alert(`Failed to deactivate App ID ${id}: ${errorMsg}`);
                }

            } catch (error) {
                console.error("Error during deactivation API call:", error);
                alert("Network error: Could not communicate with the API during deactivation.");
            }
        }
    }

     function handleLogout() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('username');
        window.location.href = "../index.html";
    }

    // --- Event Listeners and Initialization ---

    // --- Variable Assignments ---
    sidebar = document.getElementById('sidebar');
    menuToggle = document.getElementById('menu-toggle');
    backdrop = document.getElementById('sidebar-backdrop');
    appModalOverlay = document.getElementById('app-modal-overlay');
    addAppBtn = document.getElementById('add-app-btn');
    closeModalBtn = document.getElementById('close-modal-btn');
    appForm = document.getElementById('app-form');
    tableBody = document.getElementById('app-table-body');
    countSpan = document.getElementById('app-count');
    errorMessageP = document.getElementById('app-error-message');
    searchInput = document.getElementById('search-input');

    // Form Fields for Edit/Add
    appIdHidden = document.getElementById('app-id-hidden');
    appNameInput = document.getElementById('app-name');
    fiduciarySelect = document.getElementById('fiduciary-select');
    appEmailInput = document.getElementById('app-email');
    appPhoneInput = document.getElementById('app-phone');
    processingPurposeInput = document.getElementById('processing-purpose');
    dpaReferenceInput = document.getElementById('dpa-reference');

    // --- Event Listener Attachments ---
    menuToggle.addEventListener('click', toggleMenu);
    backdrop.addEventListener('click', toggleMenu);
    addAppBtn.addEventListener('click', () => showModal('Add New App'));
    closeModalBtn.addEventListener('click', closeModal);

    // --- Search Functionality ---
    searchInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            const searchTerm = searchInput.value.trim();
            loadApps(searchTerm);
        }
    });

    // --- Initialization Call ---
    loadApps();

     // 5. Handle Form Submission
    appForm.addEventListener('submit', async function(event) {
        event.preventDefault();

        const formData = new FormData(appForm);
        const data = Object.fromEntries(formData.entries());

        const isEditing = !!data.appId;
        const func = isEditing ? "update_app" : "create_app";

        const payload = {
            "_func": func,
            "app_id": data.appId,
            "fiduciary_id": data.fiduciary_id,
            "name": data.name,
            "email": data.email,
            "phone": data.phone,
            "processing_purposes": data.processing_purpose,
            "dpa_reference": data.dpa_reference
        };

        // Clean up payload if creating (remove ID)
        if (!isEditing) {
            delete payload.app_id;
            if (!payload.fiduciary_id) {
                alert("Please select an Associated Data Fiduciary.");
                return;
            }
        }

        try {
            document.getElementById('save-app-btn').textContent = isEditing ? 'Updating...' : 'Saving...';
            document.getElementById('save-app-btn').disabled = true;

            const response = await fetch(API_URL_APPS, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${AUTH_TOKEN}`
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                alert(`App ${isEditing ? 'updated' : 'added'} successfully!`);
                closeModal();
                loadApps();
            } else {
                const responseData = await response.json();
                const errorMsg = responseData.message || responseData.error.message || `Status: ${response.status}`;
                alert(`Failed to ${isEditing ? 'update' : 'add'} App: ${errorMsg}`);
            }

        } catch (error) {
            console.error(`Error ${isEditing ? 'updating' : 'creating'} App:`, error);
            alert("Network error: Could not connect to API.");
        } finally {
            document.getElementById('save-app-btn').textContent = isEditing ? 'Update App' : 'Save App';
            document.getElementById('save-app-btn').disabled = false;
        }
    });

    // Expose functions globally so they can be called by inline onclick attributes
    window.editApp = editApp;
    window.deactivateApp = deactivateApp;
    window.toggleMenu = toggleMenu; // Mobile menu
