class SessionContextMemory:

    def __init__(self):
        self.intel_store = {}

    # -------------------------
    # Merge intelligence cumulatively
    # -------------------------
    def append_intel(self, session_id, new_intel):

        if not new_intel:
            return

        new_intel = new_intel.model_dump()

        # First time storing
        if session_id not in self.intel_store:
            self.intel_store[session_id] = new_intel
            return

        existing = self.intel_store[session_id]

        # Merge list-based fields
        list_fields = [
            "upiIds",
            "phishingLinks",
            "phoneNumbers",
            "bankAccounts",
            "suspiciousKeywords",
        ]

        for field in list_fields:
            existing[field] = list(
                set(existing.get(field, []) + new_intel.get(field, []))
            )

        # Keep highest confidence
        existing["confidenceScore"] = max(
            existing.get("confidenceScore", 0), new_intel.get("confidenceScore", 0)
        )

        # Append notes
        if new_intel.get("agentNotes"):
            existing["agentNotes"] = (
                existing.get("agentNotes", "") + " | " + new_intel.get("agentNotes", "")
            )

    # -------------------------
    # Get cumulative intelligence
    # -------------------------
    def get_intel(self, session_id):
        return self.intel_store.get(session_id, {})

    # -------------------------
    # Clear session
    # -------------------------
    def clear_session(self, session_id):
        if session_id in self.intel_store:
            del self.intel_store[session_id]
