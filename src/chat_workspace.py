"""Native Streamlit chat with scope-bound session history and explicit submission."""

import hashlib
import json
from dataclasses import asdict

import pandas as pd
import streamlit as st

from src.ai_assistant import ask_question


EXAMPLE_QUESTIONS = (
    "Which application has the most unresolved critical findings?",
    "What are the top five remediation priorities?",
    "Which scanning tool has the most High-severity findings?",
    "Summarize the security findings in this scope.",
)


def sync_chat_scope(state, frame, filters):
    """Clear history on any filter/data change, including while in other views."""
    digest = hashlib.sha256(pd.util.hash_pandas_object(frame, index=False).values.tobytes())
    digest.update(json.dumps(asdict(filters), sort_keys=True, default=str).encode())
    digest.update("|".join(frame.columns).encode())
    signature = digest.hexdigest()
    changed = state.get("chat_scope") not in (None, signature)
    if state.get("chat_scope") != signature:
        state["chat_messages"] = []
        state["chat_scope"] = signature
        state["chat_scope_changed"] = changed
    return changed


def clear_chat():
    st.session_state["chat_messages"] = []


def render_chat(frame):
    st.subheader("Ask SecureSight AI")
    st.write("Ask about finding counts, applications and scanners, remediation priorities, specific finding IDs, rule-based recommendations, or monthly trends.")
    st.caption(f"Analysis scope: {len(frame)} validated synthetic findings · All global filters apply. Questions and only the necessary computed results are sent to OpenAI when you submit.")
    if st.session_state.pop("chat_scope_changed", False):
        st.info("Global filters or data changed. The previous conversation was cleared so answers cannot be mistaken for the new scope.")
    st.button("Clear Chat", on_click=clear_chat, key="clear_chat")
    if frame.empty:
        st.info("No findings are available in the current scope. Broaden the global filters or use Reset Filters.")
    example = None
    with st.expander("Example questions"):
        for index, question in enumerate(EXAMPLE_QUESTIONS):
            if st.button(question, key=f"chat_example_{index}", disabled=frame.empty, width="stretch"):
                example = question
    messages = st.session_state.setdefault("chat_messages", [])
    for message in messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])
    question = st.chat_input("Ask about the current synthetic findings", max_chars=1000, disabled=frame.empty)
    question = question or example
    if question:
        with st.chat_message("user"):
            st.write(question)
        with st.chat_message("assistant"):
            with st.spinner("Analyzing the current scope…"):
                answer = ask_question(frame, question, history=messages)
            if not answer.success:
                st.warning("AI analysis is unavailable. The dashboard remains usable.")
            st.write(answer.message)
        st.session_state["chat_messages"] = (messages + [
            {"role": "user", "content": question},
            {"role": "assistant", "content": answer.message, "request": answer.request},
        ])[-40:]
