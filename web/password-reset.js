    const API_OPERATOR = '/api/v1/admin/operator';
    const verifyForm = document.getElementById('verify-form');
    const resetForm = document.getElementById('reset-form');
    const successScreen = document.getElementById('success-screen');

    // Context shared between steps
    let recoveryContext = { email: '', passphrase: '' };

    verifyForm.onsubmit = async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      const passphrase = document.getElementById('passphrase').value.trim();
      const btn = document.getElementById('verify-btn');

      btn.disabled = true;
      btn.textContent = "Verifying...";

      try {
        const res = await fetch(API_OPERATOR, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ "_func": "verify_recovery_key", "email": email, "passphrase": passphrase })
        });

        const data = await res.json();
        if (data.success) {
          recoveryContext = { email, passphrase };
          verifyForm.classList.add('hidden');
          resetForm.classList.remove('hidden');
          document.getElementById('step-description').textContent = "Step 2: Security Configuration";
        } else {
          alert("Error: " + (data.message || "Invalid verification details."));
        }
      } catch (err) { alert("Network Error"); }
      finally {
        btn.disabled = false;
        btn.textContent = "Verify & Continue";
      }
    };

    resetForm.onsubmit = async (e) => {
      e.preventDefault();
      const newPass = document.getElementById('new-password').value;
      const confirmPass = document.getElementById('confirm-password').value;
      const btn = document.getElementById('reset-btn');

      if (newPass !== confirmPass) {
        alert("Passwords do not match.");
        return;
      }

      btn.disabled = true;
      btn.textContent = "Updating...";

      try {
        const res = await fetch(API_OPERATOR, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            "_func": "reset_password_via_recovery",
            "email": recoveryContext.email,
            "passphrase": recoveryContext.passphrase,
            "new_password": newPass
          })
        });

        const data = await res.json();
        if (data.success) {
          resetForm.classList.add('hidden');
          successScreen.classList.remove('hidden');
          document.getElementById('step-description').classList.add('hidden');
        } else {
          alert("Failed to reset: " + data.message);
        }
      } catch (err) { alert("Network Error"); }
      finally { btn.disabled = false; btn.textContent = "Update Password"; }
    };
