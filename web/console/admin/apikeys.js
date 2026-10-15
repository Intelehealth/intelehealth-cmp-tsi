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
    const API_URL_KEYS = '/api/v1/admin/apikey';
    const API_URL_FIDUCIARIES_LIST = '/api/v1/admin/fiduciary';
    const API_URL_APPS_LIST = '/api/v1/admin/app';
    const AUTH_TOKEN = localStorage.getItem('authToken');
    const USER_NAME = localStorage.getItem('username');
    document.getElementById('username').textContent = USER_NAME || 'Admin User';


    // --- Global DOM Element Variables ---
    let sidebar, menuToggle, backdrop, keyModalOverlay, addKeyBtn, closeModalBtnInner, keyForm, tableBody, countSpan, errorMessageP, searchInput;
    let fiduciarySelect, appSelect, keyDescriptionInput, appRequiredMsg;
    let keyOutputSection, generatedKeyValue, generatedKeyId;
    let FiduciaryList = [];


    // --- Helper Functions ---

    function toggleMenu() {
      sidebar.classList.toggle('open');
      backdrop.classList.toggle('hidden');
    }

    function showModal(title) {
      document.getElementById('modal-title').textContent = title;
      keyForm.reset();
      keyOutputSection.classList.add('hidden'); // Hide output on open
      document.getElementById('save-key-btn').textContent = 'Generate Key';
      document.getElementById('save-key-btn').disabled = false;

      // Hide warning
      appRequiredMsg.classList.add('hidden');

      // Clear previous permissions check
      document.querySelectorAll('input[name="permissions"]').forEach(checkbox => {
        checkbox.checked = false;
      });

      // Reset app dropdown
      appSelect.innerHTML = '<option value="">-- Select Fiduciary First --</option>';
      appSelect.disabled = true;

      keyModalOverlay.style.display = 'flex';
    }

    function closeModal() {
      keyModalOverlay.style.display = 'none';
      loadKeys(); // Reload key list after closing modal
    }

    function createStatusBadge(status) {
      let colorClass = '';
      switch (status) {
        case 'ACTIVE':
          colorClass = 'bg-green-100 text-green-800';
          break;
        case 'REVOKED':
          colorClass = 'bg-red-100 text-red-800';
          break;
        default:
          colorClass = 'bg-gray-100 text-gray-800';
      }
      return `<span class="px-3 py-1 text-xs font-medium rounded-full ${colorClass}">${esc(status)}</span>`;
    }

    function getFiduciaryName(id) {
      const fiduciary = FiduciaryList.find(f => f.fiduciary_id === id);
      return fiduciary ? fiduciary.name : 'Unknown/System Entity';
    }

    function createKeyRow(key) {
        const row = document.createElement('tr');

        const keyHashSuffix = (key.key_id || 'XXXXXXXX').slice(-4);
        const showRevoke = key.status === 'ACTIVE' || key.status === 'PENDING';

        // If app_id is present, display ID (or ideally map name if available).
        // If no app (which shouldn't happen with new logic, but legacy keys might exist), display "Direct".
        const targetEntity = key.app_name;
        
        const actionsHtml = `
            ${showRevoke ?
                `<button class="revoke-key-btn text-red-600 hover:text-red-900 font-medium text-sm" data-key-id="${esc(key.key_id)}">Revoke</button>`
                : `<span class="text-gray-500 text-xs">Revoked</span>`}
        `;

        row.innerHTML = `
            <td class="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">...${esc(keyHashSuffix)}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${esc(getFiduciaryName(key.fiduciary_id))}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${esc(targetEntity)}</td>
            <td class="px-4 py-3 text-sm text-gray-600">
                ${esc(key.permissions ? key.permissions.join(', ') : 'None')}
            </td>
            <td class="px-4 py-3 whitespace-nowrap text-sm">${createStatusBadge(key.status)}</td>
            <td class="px-4 py-3 whitespace-nowrap text-sm">
                ${actionsHtml}
            </td>
        `;
        const revokeBtn = row.querySelector('.revoke-key-btn');
        if (revokeBtn) revokeBtn.addEventListener('click', () => revokeKey(key.key_id));
        return row;
    }


    // --- Core Logic ---

    // 1. Load Fiduciaries for Dropdown Population
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
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${AUTH_TOKEN}`
          },
          body: JSON.stringify(payload)
        });

        if (!response.ok) {
          console.error("Failed to fetch Fiduciaries list for dropdown. Status:", response.status);
          return;
        }

        const responseData = await response.json();

        if (responseData.status === 401) {
          alert("Session Expired " + (responseData.message || "Authentication required."));
          handleLogout();
          return;
        }

        FiduciaryList = responseData.data || responseData; // Adjust based on likely backend response

        fiduciarySelect.innerHTML = '<option value="">-- Select Fiduciary --</option>';
        FiduciaryList.forEach(f => {
          const option = document.createElement('option');
          option.value = f.fiduciary_id;
          option.textContent = f.name;
          fiduciarySelect.appendChild(option);
        });
      } catch (error) {
        console.error("Error fetching Fiduciaries for dropdown:", error);
      }
    }

    // 2. Fetch Apps dynamically based on selected Fiduciary
    async function fetchAppsForFiduciary(fiduciaryId) {
        appSelect.innerHTML = '<option value="">Loading...</option>';
        appSelect.disabled = true;

        try {
            const payload = {
                "_func": "list_apps",
                "fiduciary_id": fiduciaryId,
                "status": "ACTIVE"
            };

            const response = await fetch(API_URL_APPS_LIST, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const responseData = await response.json();
                const apps = responseData.data || responseData;

                // Default: No app selected is NOT an option anymore if we enforce strict app keys
                // But user could be creating a key for the Fiduciary's own app, which technically acts as an app of its own data.
                // However, based on requirements, we force selection.
                appSelect.innerHTML = '<option value="">-- Select App --</option>';

                apps.forEach(p => {
                    const option = document.createElement('option');
                    option.value = p.app_id;
                    option.textContent = p.name + " (" + (p.processing_purpose || 'General') + ")";
                    appSelect.appendChild(option);
                });

                if (apps.length === 0) {
                     appSelect.innerHTML = '<option value="">No Active Apps Found</option>';
                }

                appSelect.disabled = false;
            } else {
                console.error("Failed to load apps");
                appSelect.innerHTML = '<option value="">Failed to load apps</option>';
            }
        } catch (error) {
            console.error("Error fetching apps:", error);
            appSelect.innerHTML = '<option value="">Error loading apps</option>';
        }
    }


    // 3. Load Keys List
    async function loadKeys(searchTerm = "") {
      tableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">Loading API Key data...</td></tr>`;
      errorMessageP.classList.add('hidden');

      // Ensure Fiduciary list is loaded first for display names
      if (FiduciaryList.length === 0) await fetchFiduciariesForDropdown();

      try {
        const listPayload = {
          "_func": "list_api_keys",
          "search": searchTerm,
          "status": "",
          "fiduciary_id": "",
          "page": 1,
          "limit": 50
        };

        const response = await fetch(API_URL_KEYS, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${AUTH_TOKEN}`
          },
          body: JSON.stringify(listPayload)
        });

        if (!response.ok) throw new Error(`API returned status ${response.status}`);

        const responseData = await response.json();
        const keys = responseData.data || responseData;

        if (Array.isArray(keys)) {
          tableBody.innerHTML = '';

          if (keys.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">No API Keys found matching criteria.</td></tr>`;
          } else {
            keys.forEach(key => {
              tableBody.appendChild(createKeyRow(key));
            });
          }
        } else {
          throw new Error(responseData.message || 'API returned unexpected structure.');
        }

      } catch (error) {
        console.error("Error loading API Keys:", error);
        tableBody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-red-600">
                Error connecting to the CMS API. Ensure the service is running and the token is valid.
            </td></tr>`;
        errorMessageP.classList.remove('hidden');
      }
    }

    // 4. Handle Key Revocation
    async function revokeKey(keyId) {
      if (confirm(`WARNING: Are you sure you want to REVOKE Key ID ${keyId}? This will immediately terminate access for the associated service.`)) {
        try {
          const payload = {
            "_func": "revoke_api_key",
            "key_id": keyId
          };

          const response = await fetch(API_URL_KEYS, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${AUTH_TOKEN}`
            },
            body: JSON.stringify(payload)
          });

          if (response.ok) {
            alert(`API Key ${keyId} successfully revoked.`);
            loadKeys();
          } else {
            const responseData = await response.json();
            const errorMsg = responseData.message || responseData.error.message || `Status: ${response.status}`;
            alert(`Failed to revoke Key ID ${keyId}: ${errorMsg}`);
          }

        } catch (error) {
          console.error("Error during revocation API call:", error);
          alert("Network error: Could not communicate with the API during revocation.");
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
    keyModalOverlay = document.getElementById('key-modal-overlay');
    addKeyBtn = document.getElementById('add-key-btn');
    keyForm = document.getElementById('key-form');
    tableBody = document.getElementById('key-table-body');
    countSpan = document.getElementById('key-count');
    errorMessageP = document.getElementById('key-error-message');
    searchInput = document.getElementById('search-input');
    fiduciarySelect = document.getElementById('fiduciary-select');
    appSelect = document.getElementById('app-select');
    keyDescriptionInput = document.getElementById('key-description');
    keyOutputSection = document.getElementById('key-output-section');
    generatedKeyValue = document.getElementById('generated-key-value');
    generatedKeyId = document.getElementById('generated-key-id');
    closeModalBtnInner = document.getElementById('close-modal-btn-inner');
    appRequiredMsg = document.getElementById('app-required-msg');

    // --- Event Listener Attachments ---
    menuToggle.addEventListener('click', toggleMenu);
    backdrop.addEventListener('click', toggleMenu);
    addKeyBtn.addEventListener('click', () => showModal('Generate New API Key'));
    closeModalBtnInner.addEventListener('click', closeModal);

    // Dynamic App Loading
    fiduciarySelect.addEventListener('change', (e) => {
        const selectedFiduciaryId = e.target.value;
        if (selectedFiduciaryId) {
            fetchAppsForFiduciary(selectedFiduciaryId);
        } else {
            appSelect.innerHTML = '<option value="">-- Select Fiduciary First --</option>';
            appSelect.disabled = true;
        }
    });

    // --- Search Functionality ---
    searchInput.addEventListener('keypress', function(event) {
      if (event.key === 'Enter') {
        event.preventDefault();
        const searchTerm = searchInput.value.trim();
        loadKeys(searchTerm);
      }
    });

    // --- Initialization Call ---
    loadKeys();

      // Handle Key Generation Form Submission
    keyForm.addEventListener('submit', async function(event) {
      event.preventDefault();

      const formData = new FormData(keyForm);
      const permissions = [];

      // Collect checked permissions into an array
      document.querySelectorAll('input[name="permissions"]:checked').forEach(checkbox => {
        permissions.push(checkbox.value);
      });

      if (permissions.length === 0) {
        alert("Please select at least one permission scope for the key.");
        return;
      }

      const selectedAppId = formData.get('app_id');

      // [FIX] Validation: Ensure an app is selected
      if (!selectedAppId || selectedAppId === "") {
          appRequiredMsg.classList.remove('hidden');
          alert("Error: You must select a valid App to generate a key.");
          return;
      } else {
          appRequiredMsg.classList.add('hidden');
      }

      const payload = {
        "_func": "generate_api_key",
        "fiduciary_id": formData.get('fiduciary_id'),
        "app_id": selectedAppId,
        "description": formData.get('description'),
        "permissions": permissions
      };

      try {
        document.getElementById('save-key-btn').textContent = 'Generating...';
        document.getElementById('save-key-btn').disabled = true;

        const response = await fetch(API_URL_KEYS, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${AUTH_TOKEN}`
          },
          body: JSON.stringify(payload)
        });

        const responseData = await response.json();

        if (response.ok && responseData.success && responseData.data && responseData.data.raw_api_key) {
          // Show the generated key once
          generatedKeyValue.textContent = responseData.data.raw_api_key;
          generatedKeyId.textContent = responseData.data.key_id;
          keyOutputSection.classList.remove('hidden');

          document.getElementById('save-key-btn').textContent = 'Key Generated';
          document.getElementById('save-key-btn').disabled = true; // Lock button after success
          document.getElementById('close-modal-btn-inner').textContent = 'Finish & Close';

          // Alert the user to copy the key
          alert("SUCCESS! Please copy the generated key now. It will not be shown again.");

        } else {
          const errorMsg = responseData.message || responseData.error.message || `Status: ${response.status}`;
          alert(`Failed to generate key: ${errorMsg}`);
        }

      } catch (error) {
        console.error(`Error generating key:`, error);
        alert("Network error: Could not connect to API.");
      } finally {
        // If key generation failed, allow retrying
        if (keyOutputSection.classList.contains('hidden')) {
          document.getElementById('save-key-btn').textContent = 'Generate Key';
          document.getElementById('save-key-btn').disabled = false;
        }
      }
    });



    // Expose functions globally so they can be called by inline onclick attributes
    window.revokeKey = revokeKey;
    window.toggleMenu = toggleMenu;
    window.handleLogout = handleLogout;
