// P12-08: the CSP (script-src 'self') blocks inline event-handler attributes, so the
// page's static controls carry data-action / data-change-action and are wired here.
// Handlers resolve their target functions at event time, exactly as the old attributes did.
(function wireStaticHandlers() {
    const clickHandlers = {
        initializeVoiceTour: () => initializeVoiceTour(),
        reload: () => location.reload(),
    };
    document.querySelectorAll('[data-action]').forEach((el) => {
        const fn = clickHandlers[el.getAttribute('data-action')];
        if (fn) el.addEventListener('click', (e) => fn(el, e));
    });
})();

        let config = { cmsKey: '', cmsSecret: '', policyId: '', sarvamKey: '', apiBase: window.location.origin };
        let allPurposes = [];
        let currentIndex = 0;
        let responses = {};
        let currentAudio = null;
        let recognition = null;
        let sessionState = 'IDLE'; // IDLE, SPEAKING, LISTENING, PROCESSING

        const micBtn = document.getElementById('mic-trigger');
        const statusLabel = document.getElementById('status-label');
        const transcriptPreview = document.getElementById('transcript-preview');
        const stepIndicator = document.getElementById('step-indicator');
        const progressFill = document.getElementById('progress-fill');
        const purposeNameEl = document.getElementById('purpose-name');
        const purposeDescEl = document.getElementById('purpose-desc');
        const subStatus = document.getElementById('sub-status');
        
        // Setup Web Speech Recognition
        if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
            const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
            recognition = new SpeechRecognition();
            // REFINED: Set continuous to false for clearer "turn-based" interaction
            recognition.continuous = false; 
            recognition.interimResults = true; 
            recognition.lang = 'en-IN'; 

            recognition.onresult = (event) => {
                if (sessionState !== 'LISTENING') return;
                
                let interimTranscript = '';
                for (let i = event.resultIndex; i < event.results.length; ++i) {
                    const text = event.results[i][0].transcript.toLowerCase();
                    if (event.results[i].isFinal) {
                        handleSpeechAffirmation(text);
                    } else {
                        interimTranscript += text;
                        transcriptPreview.textContent = `"${interimTranscript}..."`;
                        // Responsive matching
                        if (checkKeywords(interimTranscript)) {
                            handleSpeechAffirmation(interimTranscript);
                        }
                    }
                }
            };

            recognition.onend = () => {
                micBtn.classList.remove('recording');
                // Re-start ONLY if we are still waiting for an answer and haven't matched yet
                if (sessionState === 'LISTENING') {
                    statusLabel.textContent = "Listening (speak now)...";
                    setTimeout(() => {
                        if (sessionState === 'LISTENING') {
                            try { recognition.start(); micBtn.classList.add('recording'); } catch(e) {}
                        }
                    }, 400);
                }
            };

            recognition.onerror = (e) => {
                if (e.error !== 'no-speech') console.warn("STT Engine Error:", e.error);
            };
        }

        async function initializeVoiceTour() {
            config.cmsKey = document.getElementById('cms-key').value.trim();
            config.cmsSecret = document.getElementById('cms-secret').value.trim();
            config.policyId = document.getElementById('policy-id').value.trim();
            config.sarvamKey = document.getElementById('sarvam-key').value.trim();

            if(!config.cmsKey || !config.policyId) return alert("API Key and Policy ID are required.");

            document.getElementById('setup-modal').style.display = 'none';
            document.getElementById('interaction-ui').classList.remove('hidden');

            await fetchPolicyAndStart();
        }

        async function fetchPolicyAndStart() {
            try {
                const res = await fetch(`${config.apiBase}/api/v1/client/policy`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': config.cmsKey, 'X-API-Secret': config.cmsSecret },
                    body: JSON.stringify({ "_func": "get_policy", "policy_id": config.policyId })
                });
                const data = await res.json();
                const content = typeof data.policy_content === 'string' ? JSON.parse(data.policy_content) : data.policy_content;
                const lang = Object.keys(content)[0];
                allPurposes = content[lang].data_processing_purposes;

                if(!allPurposes || allPurposes.length === 0) return alert("No purposes found.");
                
                runPurposeLoop();
            } catch (e) { alert("Registry connection failed."); }
        }

        /**
         * Main Interaction Logic
         * Strict separation between Speaking and Listening to eliminate echo.
         */
        async function runPurposeLoop() {
            if (currentIndex >= allPurposes.length) {
                sessionState = 'PROCESSING';
                await finishInteraction();
                return;
            }

            // 1. KILL ALL ACTIVE INPUTS
            sessionState = 'SPEAKING';
            try { recognition.abort(); } catch(e) {}
            micBtn.classList.remove('recording');
            micBtn.disabled = true;
            transcriptPreview.textContent = "";

            const p = allPurposes[currentIndex];
            const isMandatory = p.is_mandatory_for_service;
            
            updateUI(p);
            
            statusLabel.textContent = "System Speaking...";
            const speechText = isMandatory 
                ? `Purpose: ${p.name}. ${p.description}. This is mandatory. Say YES to acknowledge.`
                : `Purpose: ${p.name}. ${p.description}. Say YES or NO.`;

            // 2. Play Audio and WAIT for complete silence
            await speakPurpose(speechText);

            // 3. SECURE COOLDOWN (prevents echo capture)
            await new Promise(r => setTimeout(r, 600));

            // 4. ACTIVATE MICROPHONE
            sessionState = 'LISTENING';
            statusLabel.textContent = "Listening (Speak Now)...";
            micBtn.classList.add('recording');
            micBtn.disabled = false;
            try { recognition.start(); } catch(e) {}
        }

        function updateUI(p) {
            purposeNameEl.textContent = p.is_mandatory_for_service ? `[MANDATORY] ${p.name}` : p.name;
            purposeDescEl.textContent = `"${p.description}"`;
            stepIndicator.textContent = `Purpose ${currentIndex + 1} of ${allPurposes.length}`;
            progressFill.style.width = `${((currentIndex + 1) / allPurposes.length) * 100}%`;
            
            purposeNameEl.className = p.is_mandatory_for_service 
                ? "text-[10px] font-black text-indigo-600 uppercase tracking-widest mb-3 italic"
                : "text-[10px] font-black text-teal-600 uppercase tracking-widest mb-3 italic";
        }

        async function speakPurpose(text) {
            if (!config.sarvamKey) return new Promise(r => setTimeout(r, 2000));
            try {
                const response = await fetch("https://api.sarvam.ai/text-to-speech", {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "api-subscription-key": config.sarvamKey },
                    body: JSON.stringify({
                        inputs: [text],
                        target_language_code: "en-IN",
                        speaker: "vidya",
                        speech_sample_rate: 16000,
                        model: "bulbul:v2"
                    })
                });

                const data = await response.json();
                if(data.audios && data.audios[0]) {
                    if (currentAudio) currentAudio.pause();
                    const audioSrc = "data:audio/wav;base64," + data.audios[0];
                    currentAudio = new Audio(audioSrc);
                    return new Promise((resolve) => {
                        currentAudio.onended = () => resolve();
                        currentAudio.onerror = () => resolve();
                        currentAudio.play().catch(() => resolve());
                    });
                }
            } catch (e) { console.error("TTS Error:", e); }
            return new Promise(r => setTimeout(r, 1500));
        }

        function checkKeywords(text) {
            const t = text.toLowerCase();
            return t.includes("yes") || t.includes("agree") || t.includes("accept") || t.includes("ok") || t.includes("हां") || t.includes("ஆம்");
        }

        async function handleSpeechAffirmation(transcript) {
            if (sessionState !== 'LISTENING') return;
            
            const text = transcript.toLowerCase();
            const isAffirmative = checkKeywords(text);
            const isNegative = text.includes("no") || text.includes("deny") || text.includes("skip") || text.includes("नहीं") || text.includes("இல்லை");

            if (isAffirmative || isNegative) {
                sessionState = 'PROCESSING';
                try { recognition.abort(); } catch(e) {}
                micBtn.classList.remove('recording');
                transcriptPreview.textContent = `"${transcript}"`;
                
                const p = allPurposes[currentIndex];
                responses[p.id] = isAffirmative;
                
                const isFinalPurpose = currentIndex === allPurposes.length - 1;
                statusLabel.textContent = "Processing Result...";

                if (isFinalPurpose) {
                    await speakPurpose("Thank you. Submitting your choices.");
                    currentIndex++; 
                    await finishInteraction();
                } else {
                    await speakPurpose("Acknowledgement received.");
                    currentIndex++;
                    setTimeout(runPurposeLoop, 200);
                }
            }
        }

        async function finishInteraction() {
            subStatus.textContent = "Finalising Artifact...";
            purposeNameEl.textContent = "COMPLIANCE SYNC";
            purposeDescEl.textContent = "Updating the immutable registry with your voice choices...";
            
            const dataPointConsents = allPurposes.map(p => ({
                data_point_id: p.id,
                consent_granted: !!responses[p.id],
                purpose_agreed_to: p.name, 
                timestamp_updated: new Date().toISOString()
            }));

            const payload = {
                _func: "record_consent",
                user_id: localStorage.getItem('tsi_dpdp_cms_principal_id') || "voice_user_" + Date.now(),
                policy_id: config.policyId,
                language_selected: "en",
                consent_mechanism: "VOICE_AFFIRMATION",
                data_point_consents: dataPointConsents
            };

            try {
                const response = await fetch(`${config.apiBase}/api/v1/client/consent`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-Key': config.cmsKey, 'X-API-Secret': config.cmsSecret },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    document.getElementById('completion-screen').classList.remove('hidden');
                } else {
                    const err = await response.json();
                    alert("Registry Sync Error: " + (err.message || "Please check server logs."));
                }
            } catch(e) { 
                alert("Network Error during sync.");
            }
        }
