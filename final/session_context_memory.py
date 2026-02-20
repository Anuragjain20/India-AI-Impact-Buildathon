class SessionContextMemory:

    def __init__(self):
        self.intel_store = {}

    def append_intel(self, session_id, new_intel):

        if not new_intel:
            return

        new_intel = new_intel.model_dump()

        if session_id not in self.intel_store:
            self.intel_store[session_id] = new_intel
            return

        existing = self.intel_store[session_id]

        list_fields = [
            "upiIds",
            "phishingLinks",
            "phoneNumbers",
            "bankAccounts",
            "suspiciousKeywords"
        ]

        for field in list_fields:
            existing[field] = list(
                set(existing.get(field, []) + new_intel.get(field, []))
            )

        existing["scamDetected"] = (
            existing.get("scamDetected", False)
            or new_intel.get("scamDetected", False)
        )

        existing["confidenceScore"] = max(
            existing.get("confidenceScore", 0),
            new_intel.get("confidenceScore", 0)
        )

        new_note = (new_intel.get("agentNotes") or "").strip()
        if new_note:
            current_notes = [
                note.strip()
                for note in (existing.get("agentNotes") or "").split("|")
                if note.strip()
            ]
            if new_note not in current_notes:
                current_notes.append(new_note)
            existing["agentNotes"] = " | ".join(current_notes)

    def get_intel(self, session_id):
        return self.intel_store.get(session_id, {})

    def clear_session(self, session_id):
        if session_id in self.intel_store:
            del self.intel_store[session_id]
