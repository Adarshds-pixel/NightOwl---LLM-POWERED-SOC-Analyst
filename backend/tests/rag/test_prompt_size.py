"""Chat requests must fit the provider's per-request ceiling.

19 Oct 2026: a follow-up question on a real PsExec capture (3,000-character
encoded command line, five related events, earlier answers) came to 8,012
tokens and the free Groq tier (8,000 tokens a minute) refused it.
"""
from app.rag import prompts

LONG = "A" * 6000


def _rendered(messages) -> int:
    return sum(len(m.content) for m in messages)


def test_chat_prompt_with_huge_evidence_and_history_stays_bounded():
    incident = {
        "description": "Service ImagePath Set to a Shell or Script Command (Registry) on IEWIN7",
        "command_line": LONG,
        "event_details": [f"Field{i}: {'x' * 240}" for i in range(15)],
        "related_events": [LONG for _ in range(5)],
    }
    chunks = [{"document": "d" * 952, "metadata": {"source_type": "mitre_technique", "technique_id": "T1543.003"}, "score": 0.6} for _ in range(5)]
    history = [{"role": "user" if i % 2 == 0 else "assistant", "content": "y" * 4000} for i in range(10)]

    total_chars = _rendered(prompts.build_chat_prompt(incident, chunks, history, "Which technique is this?"))

    # about 4 characters per token; 952 is the largest knowledge-base chunk.
    # Stay near 6,000 tokens so the reply fits under the 8,000-token ceiling.
    assert total_chars / 4 < 6000, total_chars


def test_chat_history_turns_are_shortened_but_the_newest_turns_are_kept():
    history = [{"role": "assistant", "content": "z" * 5000}, {"role": "user", "content": "short question"}]
    text = prompts.format_chat_history(history)
    assert "earlier answer shortened" in text
    assert "short question" in text
    assert len(text) < prompts.CHAT_TURN_CHARS + 200


def test_chat_history_as_a_whole_is_capped_newest_first():
    history = [{"role": "user", "content": f"turn {i} " + "w" * 1000} for i in range(10)]
    text = prompts.format_chat_history(history)
    assert len(text) <= prompts.CHAT_HISTORY_CHARS + prompts.CHAT_TURN_CHARS
    assert "turn 9 " in text and "turn 0 " not in text
