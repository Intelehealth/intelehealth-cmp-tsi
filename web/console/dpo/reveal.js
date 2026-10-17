// Logged reveal (reveal_user_id), shared by the DPO console pages that show principal
// identifiers (principals, compliance, grievances). Load it with <script src="reveal.js">
// before the page's own script.
//
// Console reads carry masked principal identifiers and no IP. A DPO or administrator sees
// a value in the clear only through reveal_user_id, which writes an audit row before
// answering and allows 20 reveals a minute. A revealed value lives only in the page
// (re-masked after REMASK_MS) and is never written to localStorage.
(function () {
    const API_URL_PII = '/api/v1/admin/pii';
    const LABEL = 'Reveal — this action is logged';
    const REMASK_MS = 30000;
    const canReveal = ['DPO', 'ADMIN'].includes(String(localStorage.getItem('role') || '').toUpperCase());
    let confirmed = false;

    // A Reveal button wired through the page's data-action map, or null for a role that
    // cannot reveal. `data` becomes data-* attributes.
    function button(action, data, className) {
        if (!canReveal) return null;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = className || 'reveal-btn ml-1 text-xs text-amber-700 hover:text-amber-900 underline';
        btn.textContent = LABEL;
        btn.setAttribute('data-action', action);
        Object.entries(data || {}).forEach(([k, v]) => {
            if (v != null && v !== '') btn.setAttribute(`data-${k}`, v);
        });
        return btn;
    }

    // The fiduciary a reveal names: the record's own, else the console's stored one (a
    // global ADMIN may have none stored).
    function fiduciaryFor(fiduciaryId) {
        return fiduciaryId || localStorage.getItem('fiduciary_id');
    }

    // The revealed fields of one record, or null (declined, refused or failed: the reason
    // is shown). `key` is the record id, or the user_ref for source data_principal.
    async function fields(source, key, fiduciaryId) {
        if (!canReveal || !key) return null;
        if (!confirmed) {
            if (!confirm("This reveal will be recorded in the audit log against your account. Continue?")) return null;
            confirmed = true;
        }
        const payload = { "_func": "reveal_user_id", "source": source, "fiduciary_id": fiduciaryFor(fiduciaryId) };
        if (source === 'data_principal') payload.user_ref = key; else payload.id = key;
        let response;
        let body = {};
        try {
            response = await fetch(API_URL_PII, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('authToken')}` },
                body: JSON.stringify(payload)
            });
            try { body = await response.json(); } catch (e) { body = {}; }
        } catch (e) {
            alert("Reveal failed: the server could not be reached.");
            return null;
        }
        if (response.status === 429) {
            alert("Too many reveals: you may reveal at most 20 values a minute. Wait a minute, then try again.");
            return null;
        }
        if (response.status === 403) {
            alert("You do not have permission to reveal this value. Only a DPO or an administrator may.");
            return null;
        }
        if (!response.ok) {
            alert("Reveal failed: " + (body.message || `status ${response.status}`));
            return null;
        }
        return body.fields || {};
    }

    // Puts each [element, value] in place of the element's masked text, disables `buttons`,
    // and masks again after REMASK_MS (unless the element was re-rendered meanwhile).
    function show(pairs, buttons) {
        const originals = pairs.map(([node]) => node.textContent);
        const shown = pairs.map(([node, value]) => {
            node.textContent = value == null || value === '' ? 'N/A' : String(value);
            return node.textContent;
        });
        (buttons || []).forEach(b => { b.disabled = true; });
        setTimeout(() => {
            pairs.forEach(([node], i) => { if (node.textContent === shown[i]) node.textContent = originals[i]; });
            (buttons || []).forEach(b => { b.disabled = false; });
        }, REMASK_MS);
    }

    // Reveals the principal of one record into `target`, from `btn`.
    async function into(btn, source, key, target, fiduciaryId) {
        btn.disabled = true;
        const result = await fields(source, key, fiduciaryId);
        if (!result || !target || !target.isConnected) { btn.disabled = false; return; }
        show([[target, result.user_id]], [btn]);
    }

    window.DpoReveal = Object.freeze({ LABEL, canReveal, button, fields, show, into });
})();
