// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        copyCode: (el) => copyCode(el.getAttribute('data-arg')),
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
})();

    function copyCode(id) {
        const text = document.getElementById(id).innerText;
        const dummy = document.createElement("textarea");
        document.body.appendChild(dummy);
        dummy.value = text;
        dummy.select();
        document.execCommand("copy");
        document.body.removeChild(dummy);

        const btn = event.target;
        const originalText = btn.innerText;
        btn.innerText = "COPIED!";
        btn.style.color = "#10b981";
        setTimeout(() => {
            btn.innerText = originalText;
            btn.style.color = "";
        }, 2000);
    }
