from datetime import datetime


class SessionMemory:

    def __init__(self, max_history=20):
        """
        max_history -> limits stored messages per session
        Helps control token size and memory growth
        """
        self.sessions = {}
        self.max_history = max_history

    def add_message(self, session_id, sender, text):

        if session_id not in self.sessions:
            self.sessions[session_id] = []

        self.sessions[session_id].append({
            "sender": sender,
            "text": text,
            "timestamp": datetime.utcnow().isoformat()
        })

        if len(self.sessions[session_id]) > self.max_history:
            self.sessions[session_id] = self.sessions[session_id][-self.max_history:]

    def get_history(self, session_id):
        return self.sessions.get(session_id, [])

    def get_formatted_history(self, session_id):

        history = self.sessions.get(session_id, [])

        formatted = []
        for msg in history:
            formatted.append(f"{msg['sender']}: {msg['text']}")

        return "\n".join(formatted)

    def clear_session(self, session_id):

        if session_id in self.sessions:
            del self.sessions[session_id]

    def session_exists(self, session_id):
        return session_id in self.sessions

    def total_sessions(self):
        return len(self.sessions)
