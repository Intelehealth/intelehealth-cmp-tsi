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

const API_URL = '/api/v1/admin/fiduciary';
const AUTH_TOKEN = localStorage.getItem('authToken');
const USER_NAME = localStorage.getItem('username');
// set user name
document.getElementById('username').textContent = USER_NAME;
//console.log(AUTH_TOKEN);

// --- DOM Elements ---
let sidebar;
let menuToggle;
let backdrop;
let fiduciaryModalOverlay;
let addFiduciaryBtn;
let closeModalBtn;
let fiduciaryForm;
let tableBody;
let countSpan;
let errorMessageP;

// --- Form Fields for Edit/Add ---
let fiduciaryIdHidden;
let fiduciaryNameInput;
let primaryDomainInput;
let cmsCnameInput;
let contactEmailInput;
let contactPhoneInput;

function toggleMenu() {
    sidebar.classList.toggle('open');
    backdrop.classList.toggle('hidden');
}

function showModal(title, isEdit = false) {
    document.getElementById('modal-title').textContent = title;
    fiduciaryForm.reset();
    fiduciaryIdHidden.value = ''; // Clear hidden ID by default
    if(primaryDomainInput.disabled){
      primaryDomainInput.disabled = false;
      cmsCnameInput.disabled = false;
    }

    if (isEdit) {
         document.getElementById('save-fiduciary-btn').textContent = 'Update Fiduciary';
    } else {
         document.getElementById('save-fiduciary-btn').textContent = 'Save Fiduciary';
    }

    fiduciaryModalOverlay.style.display = 'flex';
}

function closeModal() {
    fiduciaryModalOverlay.style.display = 'none';
}

function createStatusBadge(status) {
    let colorClass = '';
    switch (status) {
        case 'ACTIVE':
            colorClass = 'bg-green-100 text-green-800';
            break;
        case 'PENDING':
            colorClass = 'bg-yellow-100 text-yellow-800';
            break;
        case 'INACTIVE':
        case 'REVOKED':
            colorClass = 'bg-red-100 text-red-800';
            break;
        case 'VALIDATED':
            colorClass = 'bg-blue-100 text-blue-800';
            break;
        default:
            colorClass = 'bg-gray-100 text-gray-800';
    }
    return `<span class="px-3 py-1 text-xs font-medium rounded-full ${colorClass}">${esc(status)}</span>`;
}

function createFiduciaryRow(fiduciary) {
    const row = document.createElement('tr');

    // Determine if the Deactivate button should be shown
    const showDeactivate = fiduciary.status === 'ACTIVE' || fiduciary.status === 'PENDING';

    const actionsHtml = `
        <button class="edit-fiduciary-btn text-indigo-600 hover:text-indigo-900 font-medium text-sm mr-2">Edit</button>
        ${showDeactivate ?
            `<button class="deactivate-fiduciary-btn text-red-600 hover:text-red-900 font-medium text-sm">Deactivate</button>`
            : `<span class="text-gray-500 text-xs">Access Suspended</span>`}
    `;

    row.innerHTML = `
        <td class="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">${esc(fiduciary.name || 'N/A')}</td>
        <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${esc(fiduciary.primary_domain || 'N/A')}</td>
        <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-600">${esc(fiduciary.cms_cname || 'N/A')}</td>
        <td class="px-4 py-3 whitespace-nowrap text-sm">${createStatusBadge(fiduciary.status)}</td>
       <!-- <td class="px-4 py-3 whitespace-nowrap text-sm">${createStatusBadge(fiduciary.domain_validation_status || 'PENDING')}</td> -->
        <td class="px-4 py-3 whitespace-nowrap text-sm">
            ${actionsHtml}
        </td>
    `;
    row.querySelector('.edit-fiduciary-btn').addEventListener('click', () => editFiduciary(fiduciary.fiduciary_id));
    const deactivateBtn = row.querySelector('.deactivate-fiduciary-btn');
    if (deactivateBtn) deactivateBtn.addEventListener('click', () => deactivateFiduciary(fiduciary.fiduciary_id));
    return row;
}


// --- Core Logic ---

async function loadFiduciaries(searchTerm = "") {
    tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">Loading Fiduciary data...</td></tr>`;
    errorMessageP.classList.add('hidden');

    try {
        // The provided cURL uses POST with a JSON body for listing.
        const listPayload = {
            "_func": "list_fiduciaries",
            "status": "",
            "search": searchTerm,
            "page": 1,
            "limit": 50
        };

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AUTH_TOKEN}`
            },
            body: JSON.stringify(listPayload)
        });

        if (!response.ok) {
            throw new Error(`API returned status ${response.status}`);
        }

        const responseData = await response.json();

        if (responseData.status === 401) {
            alert("Session Expired: " + (responseData.message || "Authentication required."));
            handleLogout();
            return;
         }

        // Assuming responseData structure is: { success: true, data: [{...}, {...}] }
        if (Array.isArray(responseData)) {
            const fiduciaries = responseData;
            tableBody.innerHTML = ''; // Clear loading message

            if (fiduciaries.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-gray-500">No Fiduciaries registered yet.</td></tr>`;
            } else {
                fiduciaries.forEach(fiduciary => {
                    tableBody.appendChild(createFiduciaryRow(fiduciary));
                });
                countSpan.textContent = `Showing 1 - ${fiduciaries.length} of ${fiduciaries.length} Total`;
            }
        } else {
            // Handle API-level error (e.g., success: false)
            throw new Error(responseData.message || 'API returned success: false.');
        }

    } catch (error) {
        console.error("Error loading Fiduciaries:", error);
        tableBody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-red-600">
            Error connecting to the CMS API. Ensure the service is running and the token is valid.
        </td></tr>`;
        errorMessageP.classList.remove('hidden');
        countSpan.textContent = '0 Total';
    }
}


// Function to fetch a single Fiduciary record
async function fetchFiduciaryDetails(fiduciaryId) {
    try {
        const payload = {
            "_func": "get_fiduciary",
            "fiduciary_id": fiduciaryId
        };

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AUTH_TOKEN}`
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch details for ${fiduciaryId}. Status: ${response.status}`);
        }

        const responseData = await response.json();

        if (responseData.name) {
            return responseData;
        } else {
            throw new Error(responseData.message || 'Fiduciary details not found.');
        }
    } catch (error) {
        console.error("Error fetching Fiduciary details:", error);
        alert(`Failed to load details for editing: ${error.message}`);
        return null;
    }
}

// Placeholder functions (for demo only)
async function editFiduciary(id) {
     // 1. Show modal in loading state
     showModal('Edit Data Fiduciary', true);

    // 2. Fetch specific fiduciary data
    const fiduciary = await fetchFiduciaryDetails(id);

    if (fiduciary) {
        // 3. Populate form fields
        fiduciaryIdHidden.value = fiduciary.fiduciary_id;
        fiduciaryNameInput.value = fiduciary.name || '';
        primaryDomainInput.value = fiduciary.primary_domain || '';
        cmsCnameInput.value = fiduciary.cms_cname || '';
        contactEmailInput.value = fiduciary.email || '';
        contactPhoneInput.value = fiduciary.phone || '';
        //statusSelect.value = fiduciary.status || 'ACTIVE'; // Fallback to ACTIVE

        // Keep domain fields disabled during edit
        primaryDomainInput.disabled = true;
        cmsCnameInput.disabled = true;

    } else {
        // If fetch failed, close the modal
        closeModal();
    }
}

async function deactivateFiduciary(id) {
    if (confirm(`Are you sure you want to DEACTIVATE Fiduciary ID ${id}? This will suspend all consent operations.`)) {
        try {
            const payload = {
                "_func": "delete_fiduciary",
                "fiduciary_id": id
            };

            const response = await fetch(API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${AUTH_TOKEN}`
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                alert(`Fiduciary ID ${id} successfully deactivated.`);
                loadFiduciaries(); // Reload list to reflect status change
            } else {
                const responseData = await response.json();
                const errorMsg = responseData.message || responseData.error.message || `Status: ${response.status}`;
                alert(`Failed to deactivate Fiduciary ID ${id}: ${errorMsg}`);
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
fiduciaryModalOverlay = document.getElementById('fiduciary-modal-overlay');
addFiduciaryBtn = document.getElementById('add-fiduciary-btn');
closeModalBtn = document.getElementById('close-modal-btn');
closeModalBtn = document.getElementById('close-modal-btn');
fiduciaryForm = document.getElementById('fiduciary-form');
tableBody = document.getElementById('fiduciary-table-body');
countSpan = document.getElementById('fiduciary-count');
errorMessageP = document.getElementById('fiduciary-error-message');
searchInput = document.getElementById('search-input');

// Form Fields for Edit/Add
fiduciaryIdHidden = document.getElementById('fiduciary-id-hidden');
fiduciaryNameInput = document.getElementById('fiduciary-name');
primaryDomainInput = document.getElementById('fiduciary-domain');
cmsCnameInput = document.getElementById('fiduciary-cname');
contactEmailInput = document.getElementById('fiduciary-email');
contactPhoneInput = document.getElementById('fiduciary-phone');


// --- Event Listener Attachments (Moved inside DOMContentLoaded) ---
menuToggle.addEventListener('click', toggleMenu);
backdrop.addEventListener('click', toggleMenu);
addFiduciaryBtn.addEventListener('click', () => showModal('Add New Data Fiduciary'));
closeModalBtn.addEventListener('click', closeModal);

// --- Search Functionality ---
searchInput.addEventListener('keypress', function(event) {
    // Key code 13 is the Enter key
    if (event.key === 'Enter') {
        event.preventDefault();
        const searchTerm = searchInput.value.trim();
        loadFiduciaries(searchTerm);
    }
});

// --- Initialization Call ---
loadFiduciaries();

 // Handles the Add/Edit Fiduciary form submission
fiduciaryForm.addEventListener('submit', async function(event) {
    event.preventDefault();

    const formData = new FormData(fiduciaryForm);
    const data = Object.fromEntries(formData.entries());

    const isEditing = !!data.fiduciaryId;
    const func = isEditing ? "update_fiduciary" : "create_fiduciary";

    const payload = {
        "_func": func,
        "fiduciary_id": data.fiduciaryId,
        "name": data.name,
        "email": data.email,
        "phone": data.phone,
        "primary_domain": data.primary_domain,
        "cms_cname": data.cms_cname
    };

    // Clean up payload if creating (remove ID)
    if (!isEditing) {
        delete payload.fiduciary_id;
    }

    try {
        document.getElementById('save-fiduciary-btn').textContent = isEditing ? 'Updating...' : 'Saving...';
        document.getElementById('save-fiduciary-btn').disabled = true;

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AUTH_TOKEN}`
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            alert(`Fiduciary ${isEditing ? 'updated' : 'added'} successfully!`);
            closeModal();
            loadFiduciaries(); // Reload list
        } else {
            const responseData = await response.json();
            const errorMsg = responseData.message || responseData.error.message || `Status: ${response.status}`;
            alert(`Failed to ${isEditing ? 'update' : 'add'} Fiduciary: ${errorMsg}`);
        }

    } catch (error) {
        console.error(`Error ${isEditing ? 'updating' : 'creating'} Fiduciary:`, error);
        alert("Network error: Could not connect to API.");
    } finally {
        document.getElementById('save-fiduciary-btn').textContent = isEditing ? 'Update Fiduciary' : 'Save Fiduciary';
        document.getElementById('save-fiduciary-btn').disabled = false;
    }
});

// Expose functions globally so they can be called by inline onclick attributes
window.editFiduciary = editFiduciary;
window.deactivateFiduciary = deactivateFiduciary;
