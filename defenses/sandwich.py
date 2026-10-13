"""Sandwich defense: repeat the user's request after every tool result, so the last
instruction the model reads is the user's and not one planted in the data.
(AgentDojo calls this repeat_user_prompt.)"""


def remind(text: str, user_task: str) -> str:
    return f'{text}\n\nReminder of the user\'s request: "{user_task}"'
