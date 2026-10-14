DEFAULT_NOTIFICATION_MESSAGES = {
    "CONSENT_RECORDED": {"en": "Your consent preferences were recorded."},
    "CONSENT_WITHDRAWN": {"en": "Your consent was withdrawn for one or more purposes."},
    "ERASURE_REQUEST": {"en": "Your erasure request has been submitted."},
    "PURGE_STATUS": {"en": "A data deletion request changed status."},
    "GRIEVANCE_SUBMITTED": {"en": "Your grievance has been submitted."},
    "GRIEVANCE_UPDATED": {"en": "Your grievance status was updated."},
    "BREACH_NOTIFICATION": {
        "en": "A personal data breach affecting your data was reported ({title}). What you should do: {actionable_steps}"
    },
    "CONSENT_VALIDATION_DENIED": {
        "en": "A processing request under your consent was denied because no active consent exists for that purpose."
    },
    "CONSENT_GIVEN_NOTIFICATION": {"en": "Your consent preferences were recorded."},
    "WITHDRAWAL_ACKNOWLEDGMENT": {"en": "Your consent was withdrawn for one or more purposes."},
    "ERASURE_REQUESTED_NOTIFICATION": {"en": "Your erasure request has been submitted."},
    "NOTIFICATION_DELIVERED": {"en": "A notification was delivered to you."},
    "NOTIFICATION_ACKNOWLEDGED": {"en": "You acknowledged a notification."},
    # GR-10: one notice per grievance stage.
    "GRIEVANCE_ASSIGNED": {"en": "Your grievance has been assigned to an officer."},
    # P7-05: the DPO/officer-facing notice, distinct from the principal's copy,
    # carrying the grievance reference so the assignee knows which complaint.
    "GRIEVANCE_ROUTED": {"en": "Grievance {reference_number} ({grievance_type}) has been assigned to you for action."},
    "GRIEVANCE_IN_PROGRESS": {"en": "Your grievance is being worked on."},
    "GRIEVANCE_ESCALATED": {"en": "Your grievance has been escalated because it passed its response deadline."},
    # GR-11: the resolution summary travels in the in-app notice itself. P10-07:
    # outside the app (SMS / push) the summary is replaced by a pointer to it.
    "GRIEVANCE_RESOLVED": {
        "en": "Your grievance {reference_number} has been {status_word}. Resolution summary: {resolution_details} "
        "You can rate how it was handled."
    },
    "PURPOSE_CLOSED": {
        "en": "A purpose you consented to has ended; data held only for it will be erased or de-identified."
    },
    # SA-09: an orchestrated purge nobody has confirmed.
    "PURGE_OVERDUE": {"en": "A data deletion request has not been confirmed as completed within its deadline."},
    # P10-10 / NT-01: these three were written by the services but had no
    # default, so the body delivered was the enum name itself.
    "POLICY_CHANGE_RECONSENT_REQUIRED": {
        "en": "The privacy notice you consented under has changed. Please review the new notice and confirm your "
        "consent choices; until you do, your earlier choices stay in place."
    },
    "PURGE_SCHEDULED": {
        "en": "A retention period ends within 48 hours; data held under it is scheduled for erasure or de-identification."
    },
    # Rule 6(1)(c): the DPO-facing monitoring notice.
    "SECURITY_AUTH_FAILURE_BURST": {
        "en": "{failures} failed sign-in attempts were recorded in the last {window_minutes} minutes. Review the access log."
    },
    "PURGE_EXECUTED": {
        "en": "A retention period has ended and erasure or de-identification requests were raised for the data held under it."
    },
    # s.8(6) / Rule 7(2): the DPO-facing Board intimation clock.
    "BREACH_BOARD_DEADLINE_DUE": {
        "en": "The Data Protection Board must be intimated of breach '{title}' by {deadline}. Record the intimation once made."
    },
    "BREACH_BOARD_DEADLINE_MISSED": {
        "en": "The 72-hour deadline to intimate the Data Protection Board of breach '{title}' passed at {deadline}."
    },
}

# NT-03: Hindi defaults for every principal-facing notice, so a principal who
# chose Hindi is not answered in English before the DPO has written anything.
# A DPO template in the principal's language still takes precedence, and the
# console offers every Eighth Schedule language for the DPO's own wording.
_HINDI = {
    "CONSENT_RECORDED": "आपकी सहमति संबंधी प्राथमिकताएँ दर्ज कर ली गई हैं।",
    "CONSENT_GIVEN_NOTIFICATION": "आपकी सहमति संबंधी प्राथमिकताएँ दर्ज कर ली गई हैं।",
    "CONSENT_WITHDRAWN": "एक या अधिक उद्देश्यों के लिए आपकी सहमति वापस ले ली गई है।",
    "WITHDRAWAL_ACKNOWLEDGMENT": "एक या अधिक उद्देश्यों के लिए आपकी सहमति वापस ले ली गई है।",
    "ERASURE_REQUEST": "आपका डेटा मिटाने का अनुरोध जमा कर दिया गया है।",
    "ERASURE_REQUESTED_NOTIFICATION": "आपका डेटा मिटाने का अनुरोध जमा कर दिया गया है।",
    "CONSENT_VALIDATION_DENIED": "आपकी सहमति के अंतर्गत प्रसंस्करण का एक अनुरोध अस्वीकार कर दिया गया, क्योंकि उस उद्देश्य के लिए कोई सक्रिय सहमति नहीं है।",
    "GRIEVANCE_SUBMITTED": "आपकी शिकायत दर्ज कर ली गई है।",
    "GRIEVANCE_UPDATED": "आपकी शिकायत की स्थिति बदल गई है।",
    "GRIEVANCE_ASSIGNED": "आपकी शिकायत एक अधिकारी को सौंप दी गई है।",
    "GRIEVANCE_IN_PROGRESS": "आपकी शिकायत पर कार्य चल रहा है।",
    "GRIEVANCE_ESCALATED": "उत्तर की समय-सीमा बीत जाने के कारण आपकी शिकायत को आगे बढ़ा दिया गया है।",
    "GRIEVANCE_RESOLVED": "आपकी शिकायत {reference_number} पर कार्रवाई पूरी हो गई है। समाधान का सारांश: {resolution_details} "
    "आप बता सकते हैं कि इसका निपटारा कैसा रहा।",
    "PURPOSE_CLOSED": "जिस उद्देश्य के लिए आपने सहमति दी थी वह समाप्त हो गया है; केवल उसी के लिए रखा गया डेटा मिटा दिया "
    "जाएगा या उसकी पहचान हटा दी जाएगी।",
    "POLICY_CHANGE_RECONSENT_REQUIRED": "जिस गोपनीयता सूचना के तहत आपने सहमति दी थी वह बदल गई है। कृपया नई सूचना देखें और "
    "अपनी सहमति के विकल्पों की पुष्टि करें; तब तक आपके पिछले विकल्प लागू रहेंगे।",
    "BREACH_NOTIFICATION": "व्यक्तिगत डेटा उल्लंघन की एक सूचना उपलब्ध है।",
}
for _type, _text in _HINDI.items():
    DEFAULT_NOTIFICATION_MESSAGES[_type]["hi"] = _text

# P10-10: the text used when a template's placeholders cannot be filled - a
# notice dispatched without context, or one whose context erasure has cleared -
# so a principal never receives literal {placeholders}.
PLAIN_NOTIFICATION_MESSAGES = {
    "GRIEVANCE_RESOLVED": {
        "en": "Your grievance has been resolved. Sign in to read the resolution summary.",
        "hi": "आपकी शिकायत का समाधान कर दिया गया है। समाधान का सारांश पढ़ने के लिए साइन इन करें।",
    },
    "GRIEVANCE_ROUTED": {"en": "A grievance has been assigned to you for action."},
    "SECURITY_AUTH_FAILURE_BURST": {"en": "A burst of failed sign-in attempts was recorded. Review the access log."},
    "BREACH_NOTIFICATION": {"en": "A personal data breach notification is available. Sign in to read what to do."},
    "BREACH_BOARD_DEADLINE_DUE": {"en": "A breach's Data Protection Board intimation is due within 12 hours."},
    "BREACH_BOARD_DEADLINE_MISSED": {"en": "A breach's 72-hour Data Protection Board intimation deadline has passed."},
}

# P10-07: context fields that may carry free text about the principal's health
# or circumstances. They are shown in the app only and never handed to the SMS
# or push gateway.
SENSITIVE_CONTEXT_KEYS = {"resolution_details", "actionable_steps"}
OUT_OF_BAND_PLACEHOLDER = {"en": "(sign in to read it)", "hi": "(पढ़ने के लिए साइन इन करें)"}

# NT-03: English plus the 22 Eighth Schedule languages a notice may be written in.
NOTIFICATION_LANGUAGES = (
    "en",
    "as",
    "bn",
    "brx",
    "doi",
    "gu",
    "hi",
    "kn",
    "ks",
    "kok",
    "mai",
    "ml",
    "mni",
    "mr",
    "ne",
    "or",
    "pa",
    "sa",
    "sat",
    "sd",
    "ta",
    "te",
    "ur",
)
