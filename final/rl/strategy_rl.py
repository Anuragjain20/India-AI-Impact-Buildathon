import numpy as np
import json
import os


class StrategyRL:

    FILE = "/tmp/strategy_q_table.json"

    def __init__(self):

        if os.path.exists(self.FILE):
            self.q_table = json.load(open(self.FILE))
        else:
            self.q_table = {}

        self.alpha = 0.1
        self.gamma = 0.9

    def get_q(self, state, action):
        return self.q_table.get(str((state, action)), 0)

    def choose_action(self, state, actions, epsilon=0.2):

        if np.random.rand() < epsilon:
            return np.random.choice(actions)

        qs = [self.get_q(state, a) for a in actions]
        return actions[np.argmax(qs)]

    def update(self, state, action, reward, next_state, actions):

        current = self.get_q(state, action)
        next_max = max([self.get_q(next_state, a) for a in actions])

        new_q = current + self.alpha * (reward + self.gamma * next_max - current)

        self.q_table[str((state, action))] = new_q

        json.dump(self.q_table, open(self.FILE, "w"))
