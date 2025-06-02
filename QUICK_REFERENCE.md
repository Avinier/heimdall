# Orchestration Flow - Quick Reference

## 🎯 Core Concept

**Automated Security Testing Orchestration** with 3 nested loops and intelligent context management.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  PlannerAgent   │    │  ActionerAgent  │    │ ContextManager  │
│                 │    │                 │    │                 │
│ Generates       │    │ Executes        │    │ Manages         │
│ Security Plans  │    │ Test Actions    │    │ Context & Memory│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                ┌─────────────────┴─────────────────┐
                │         WebProxy                  │
                │    Browser Automation             │
                └───────────────────────────────────┘
```

## 🔄 Three-Loop Structure

### 1. OUTER LOOP: URL Processing

```python
for url in urls_to_parse:
    navigate_to_url(url)
    extract_page_data()
    discover_new_links()
    generate_security_plans()
    # Proceed to MIDDLE LOOP
```

### 2. MIDDLE LOOP: Plan Execution

```python
for plan in security_plans:
    initialize_conversation_history()
    # Proceed to INNER LOOP
```

### 3. INNER LOOP: Action Iteration

```python
while iteration < max_iterations:
    manage_context_history()
    generate_next_action()
    execute_action()
    summarize_result()
    check_completion()
```

## 📊 Sample Data Flows

### Input → Processing → Output

**Input:**

```
URL: https://example.com
Config: {expand_scope: true, max_iterations: 10}
```

**Processing:**

```
1. Extract: Forms, Links, JS, Cookies → 15KB raw data
2. Summarize: 15KB → 1KB security-focused content
3. Plan: Generate 5 security test plans
4. Execute: 3-8 actions per plan, adaptive based on results
5. Analyze: Extract security findings from conversations
```

**Output:**

```
Summary: 5 URLs analyzed, 23 security findings
Findings: SQL injection, XSS, IDOR, Info disclosure, etc.
Token Usage: ~45,230 total tokens across entire assessment
```

## 🧠 Context Management Strategy

### Memory Preservation Pattern

```
┌─── Critical Messages (Always Keep) ────┐
│ [1] Page Context + Summary             │
│ [2] Current Plan Instructions          │
├─── Summarized Middle (When > 12) ──────┤
│ [S] VAPT summary of previous actions   │
├─── Recent Messages (Last 10) ──────────┤
│ [N-9] Action discussion               │
│ [N-8] Action result                   │
│ ...                                   │
│ [N-0] Latest action result            │
└─────────────────────────────────────────┘
```

## 🛠️ Key Methods by Agent

### PlannerAgent

```python
.plan(page_data) → List[{title, description}]
```

### ActionerAgent

```python
.generate_action_of_plan_step(plan, page_data, conversation_history)
→ {discussion, action}
```

### ContextManagerAgent

```python
.summarize_page_source(raw_html, url) → security_summary
.summarize(llm_response, tool_use, tool_output) → action_summary
.summarize_conversation(history) → condensed_history
```

## 🔍 Security Testing Categories

**Generated Plans Cover:**

1. **Authentication Bypass Testing** - Login, session management
2. **Cross-Site Scripting (XSS)** - Input validation, payload testing
3. **Authorization & Access Control** - IDOR, privilege escalation
4. **Information Disclosure** - Error handling, debug info
5. **CSRF & Session Management** - Token validation, session security

## ⚡ Performance Metrics

**Typical Performance:**

- **URL Processing**: 1-2 minutes per URL
- **Plan Execution**: 30-60 seconds per plan
- **Action Iteration**: 5-10 seconds per action
- **Context Management**: <1 second per summarization
- **Token Efficiency**: 70% reduction via intelligent summarization

## 🚀 Getting Started

### Basic Usage

```python
from orchestration2 import run_orchestration

# Run with default settings
run_orchestration()

# Custom configuration
run_orchestration(
    expand_scope=True,      # Discover and test new URLs
    max_iterations=10,      # Max actions per plan
    keep_messages=12        # Context history limit
)
```

### Key Configuration Options

```python
base_url = "https://your-target.com"  # Change target
expand_scope = True                   # Auto-discover URLs
max_iterations = 10                   # Actions per plan
keep_messages = 12                    # Context window size
```

## 🔧 Customization Points

**Agent Configuration:**

```python
planner = PlannerAgent(api_type="gemini", reasoning=True, temperature=0.3)
actioner = ActionerAgent(api_type="gemini", reasoning=True, temperature=0.3)
context_manager = ContextManagerAgent(api_type="fireworks", temperature=0.2)
```

**Tool Commands Available:**

```python
goto(page, "/path")                    # Navigate
click(page, "selector")                # Click element
fill(page, "selector", "value")        # Fill input
execute_js(page, "javascript")         # Run JS
complete()                             # Finish plan
```

## 📈 Success Indicators

**System Working Correctly When:**

- ✅ Plans generated for each URL (typically 3-5 plans)
- ✅ Actions execute without syntax errors
- ✅ Context stays under token limits via summarization
- ✅ Security findings detected and categorized
- ✅ Browser navigation succeeds across discovered URLs

**Common Issues:**

- ❌ Plan generation fails → Check LLM API connectivity
- ❌ Action execution errors → Validate tool command syntax
- ❌ Context overflow → Reduce keep_messages or improve summarization
- ❌ No findings detected → Review finding detection patterns

This orchestration system provides comprehensive, automated security testing with intelligent resource management and adaptive execution strategies.
