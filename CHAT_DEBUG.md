# AI Agent Chat Not Working — Debug Guide

## What to check in this repo

### 1) Is the Streamlit app running and showing the Chat UI?
Run:
- `python -m streamlit run cyberguard/dashboard.py --server.port=8501`

### 2) Verify the agent method works (backend check)
From the project root, run:
- `python -c "from cyberguard.agent import CyberGuardAgent; print(CyberGuardAgent().answer_query('Generate a security incident report.'))"`

This should print a long incident report text.

### 3) Known issue: broken page routing string
In `cyberguard/dashboard.py`, the radio options include:
- "🤖 AI Agent Chat"

But the page handler uses an invalid/mismatched option string:
- `elif page == "� AI Agent Chat":`

Because the strings don’t match exactly, `render_ai_chat()` never runs, so the chat UI appears broken or not functional.

### 4) Fix
Change:
```python
elif page == "� AI Agent Chat":
    render_ai_chat()
```
To:
```python
elif page == "🤖 AI Agent Chat":
    render_ai_chat()
```

## Why this fixes it
Streamlit renders only the branch that matches the exact `page` value returned from `st.radio()`.
With a mismatched string, the chat route is never selected.


