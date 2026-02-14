import json
import random
import os

class PersonaRL:

    FILE = "/tmp/persona_scores.json"

    def __init__(self):

        if not os.path.exists(self.FILE):
            self.scores = {
                "elderly": {"wins": 1, "trials": 1},
                "student": {"wins": 1, "trials": 1},
                "business_owner": {"wins": 1, "trials": 1}
            }
            self.save()
        else:
            self.scores = json.load(open(self.FILE))

    def save(self):
        json.dump(self.scores, open(self.FILE, "w"))

    def choose_persona(self, epsilon=0.2):

        if random.random() < epsilon:
            return random.choice(list(self.scores.keys()))

        return max(
            self.scores,
            key=lambda p: self.scores[p]["wins"] /
            self.scores[p]["trials"]
        )

    def update(self, persona, score):

        self.scores[persona]["wins"] += score
        self.scores[persona]["trials"] += 1
        self.save()

