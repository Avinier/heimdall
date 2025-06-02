# VAPT Orchestration Database Schema Mapping - Django Integration

## Overview

This document explains how the `run_orchestration()` function from `orchestration2.py` maps to the comprehensive database schema designed to fully integrate with the existing Django `quantumsenses` database. The schema follows Django naming conventions and provides seamless table traversal across the entire system.

## Database Integration Architecture

### Key Integration Points:

1. **User Management**: All VAPT activities link to `auth_user` table
2. **Container Infrastructure**: Direct integration with `container_*` tables
3. **Topic Management**: Links to `auth_api_app_usertopicmapping` for project organization
4. **Network Infrastructure**: Connects to `network_*` tables for network analysis
5. **Complete Audit Trail**: Full traceability from user to container to findings

### Django Table Naming Convention:

- **Old**: `vapt_orchestration_session`
- **New**: `vapt_orchestrationsession` (Django style)
- **Pattern**: `app_modelname` format for all VAPT tables

---

## Complete Table Traversal Map

### From User to All VAPT Data:

```sql
-- Traverse from user to all their VAPT activities
SELECT * FROM auth_user u
  JOIN vapt_orchestrationsession s ON u.id = s.user_id
  JOIN vapt_urldiscovery url ON s.id = url.session_id
  JOIN vapt_securityplan p ON url.id = p.url_id
  JOIN vapt_actionexecution a ON p.id = a.plan_id
  JOIN vapt_securityfinding f ON s.id = f.session_id
WHERE u.username = 'target_user';
```

### From Container to VAPT Results:

```sql
-- Traverse from container to all security findings
SELECT * FROM container_container c
  JOIN vapt_orchestrationsession s ON c.id = s.container_id
  JOIN vapt_securityfinding f ON s.id = f.session_id
  JOIN vapt_containerfindings cf ON f.id = cf.finding_id
WHERE c.id = 25;
```

### From Topic to Comprehensive Security Analysis:

```sql
-- Traverse from topic to all related security data
SELECT * FROM auth_api_app_usertopicmapping t
  JOIN container_container c ON t.id = c.topic_id
  JOIN vapt_orchestrationsession s ON c.id = s.container_id
  JOIN vapt_containersecurity cs ON c.id = cs.container_id
WHERE t.topic = 'my-project';
```

---

## Function Mapping to Database Tables

### 1. **INITIALIZATION & CONFIGURATION**

#### Function Code:

```python
def run_orchestration(expand_scope=True, max_iterations=10, keep_messages=12):
    base_url = "https://dev.quantumsenses.com"
    total_token_counter = 0

    # Initialize agents and tools
    web_proxy = WebProxy(starting_url=base_url)
    planner = PlannerAgent(...)
    actioner = ActionerAgent(...)
    context_manager = ContextManagerAgent(...)
```

#### Database Integration:

```sql
-- 1. Create session with full Django integration
INSERT INTO vapt_orchestrationsession (
    session_name, base_url, target_hostname,
    user_id, container_id, topic_id,  -- Django FKs
    expand_scope, max_iterations, keep_messages,
    status, started_at, configuration,
    created_at, updated_at, is_active
) VALUES (
    'VAPT Session 2024-01-15',
    'https://dev.quantumsenses.com',
    'dev.quantumsenses.com',
    1,    -- FK to auth_user
    25,   -- FK to container_container
    15,   -- FK to auth_api_app_usertopicmapping
    1, 10, 12, 'initializing', NOW(),
    JSON_OBJECT('expand_scope', true, 'max_iterations', 10),
    NOW(), NOW(), 1
);

-- 2. Register agents with Django integration
INSERT INTO vapt_agentinstance (
    session_id, agent_type, agent_config,
    initialization_status, created_at, updated_at, is_active
) VALUES
(1, 'planner', JSON_OBJECT('api_type', 'gemini', 'model', 'gemini-2.5-flash'), 'success', NOW(), NOW(), 1),
(1, 'actioner', JSON_OBJECT('api_type', 'gemini', 'model', 'gemini-2.5-flash'), 'success', NOW(), NOW(), 1),
(1, 'context_manager', JSON_OBJECT('api_type', 'fireworks', 'model', 'qwen3-30b'), 'success', NOW(), NOW(), 1);

-- 3. Initialize container security tracking
INSERT INTO vapt_containersecurity (
    container_id, user_id, topic_id,
    total_vapt_sessions, created_at, updated_at, is_active
) VALUES (
    25, 1, 15, 1, NOW(), NOW(), 1
) ON DUPLICATE KEY UPDATE
    total_vapt_sessions = total_vapt_sessions + 1,
    updated_at = NOW();
```

### 2. **URL DISCOVERY & PROCESSING (OUTER LOOP)**

#### Function Code:

```python
# OUTER LOOP (URL Processing)
while urls_to_parse:
    url = urls_to_parse.pop(0)
    if url in visited_urls:
        continue
    visited_urls.add(url)

    # Navigate and extract page data
    page.goto(url, wait_until='networkidle', timeout=100000)
    extractor = PageDataExtractor(page)
    raw_page_data = extractor.extract_page_data()
```

#### Database Integration:

```sql
-- Track URL discovery with container linkage
INSERT INTO vapt_urldiscovery (
    session_id, url, url_hash, discovery_source,
    discovery_iteration, status, processing_started_at,
    created_at, updated_at, is_active
) VALUES (
    1, 'https://dev.quantumsenses.com/api/users',
    SHA2('https://dev.quantumsenses.com/api/users', 256),
    'page_extraction', 1, 'processing', NOW(),
    NOW(), NOW(), 1
);

-- Store page data with enhanced tracking
INSERT INTO vapt_pagedata (
    url_id, raw_page_data, summarized_page_data,
    links_count, forms_count, api_endpoints_count,
    technology_stack, extraction_metadata,
    created_at, updated_at, is_active
) VALUES (
    1, '<!-- Full page data -->', 'Security-relevant page summary',
    15, 3, 5,
    JSON_OBJECT('framework', 'Django', 'server', 'nginx', 'database', 'MySQL'),
    JSON_OBJECT('extraction_time', 2.5, 'content_size', 45000),
    NOW(), NOW(), 1
);
```

### 3. **SECURITY PLAN GENERATION (MIDDLE LOOP)**

#### Database Integration:

```sql
-- Store security plans with enhanced categorization
INSERT INTO vapt_securityplan (
    url_id, planner_agent_id, plan_title, plan_description,
    plan_type, priority, plan_order, status,
    llm_generation_metadata, created_at, updated_at, is_active
) VALUES
(1, 1, 'SQL Injection Testing', 'Test login forms for SQL injection vulnerabilities',
 'sql_injection', 'high', 1, 'generated',
 JSON_OBJECT('model', 'gemini-2.5-flash', 'tokens', 1200, 'temperature', 0.3),
 NOW(), NOW(), 1),
(1, 1, 'XSS Vulnerability Assessment', 'Test input fields for XSS vulnerabilities',
 'xss', 'high', 2, 'generated',
 JSON_OBJECT('model', 'gemini-2.5-flash', 'tokens', 980, 'temperature', 0.3),
 NOW(), NOW(), 1);
```

### 4. **ACTION EXECUTION & ITERATION (INNER LOOP)**

#### Database Integration:

```sql
-- Track action execution with enhanced metadata
INSERT INTO vapt_actionexecution (
    plan_id, actioner_agent_id, iteration_number, action_type,
    action_command, action_discussion, target_element,
    execution_status, action_output, executed_at,
    created_at, updated_at, is_active
) VALUES (
    1, 2, 1, 'goto',
    'goto(page, "/login/")',
    'Navigating to login page to begin SQL injection testing',
    NULL, 'success',
    'Successfully navigated to /login/. Page title: Login - QuantumSenses',
    NOW(), NOW(), NOW(), 1
);

-- Store conversation with action linkage
INSERT INTO vapt_conversationhistory (
    plan_id, message_order, role, content, message_type,
    related_action_id, token_count, is_summarized,
    created_at, updated_at, is_active
) VALUES
(1, 1, 'user', 'URL: https://dev.quantumsenses.com...', 'page_context', NULL, 150, 0, NOW(), NOW(), 1),
(1, 2, 'user', 'SECURITY TEST PLAN: SQL Injection Testing...', 'plan_instructions', NULL, 300, 0, NOW(), NOW(), 1),
(1, 3, 'assistant', 'Navigating to login page to begin testing', 'action_discussion', 1, 50, 0, NOW(), NOW(), 1);
```

### 5. **SECURITY FINDINGS WITH CONTAINER INTEGRATION**

#### Database Integration:

```sql
-- Record security findings with full container context
INSERT INTO vapt_securityfinding (
    session_id, url_id, plan_id, action_id, container_id,  -- Full linkage
    finding_type, severity, title, description, technical_details,
    affected_url, payload_used, detection_method, confidence,
    status, created_at, updated_at, is_active
) VALUES (
    1, 1, 1, 3, 25,  -- Links to session, URL, plan, action, AND container
    'sql_injection', 'high', 'SQL Injection in Login Form',
    'The login form is vulnerable to SQL injection attacks',
    'Payload: admin\' OR \'1\'=\'1\' -- resulted in successful authentication bypass',
    'https://dev.quantumsenses.com/login/',
    'admin\' OR \'1\'=\'1\' --',
    'conversation_analysis', 'high',
    'new', NOW(), NOW(), 1
);

-- Link finding to specific container components
INSERT INTO vapt_containerfindings (
    finding_id, container_id, docker_image_id, container_specs_id,
    affected_component, component_details, risk_level,
    remediation_priority, affects_other_containers, deployment_impact,
    created_at, updated_at, is_active
) VALUES (
    1, 25, 5, 10,  -- Links to container, docker image, specs
    'application', 'Django authentication middleware vulnerability',
    'high', 'urgent', 0, 'medium',
    NOW(), NOW(), 1
);
```

### 6. **NETWORK TRAFFIC MONITORING WITH CONTAINER CONTEXT**

#### Database Integration:

```sql
-- Network requests with container relationship
INSERT INTO vapt_networkrequest (
    session_id, action_id, request_id, url, method,
    status_code, request_headers, response_headers,
    request_body, response_body, request_timestamp,
    duration, security_analysis, contains_sensitive_data,
    created_at, updated_at, is_active
) VALUES (
    1, 3, 'req_1642258800.123',
    'https://dev.quantumsenses.com/login/', 'POST', 200,
    JSON_OBJECT('Content-Type', 'application/x-www-form-urlencoded', 'User-Agent', 'Mozilla/5.0...'),
    JSON_OBJECT('Set-Cookie', 'sessionid=abc123', 'X-Frame-Options', 'DENY'),
    'username=admin&password=admin\' OR \'1\'=\'1\' --',
    '{"status": "success", "redirect": "/dashboard/"}',
    NOW(), 0.5,
    'Successful SQL injection bypass detected in response',
    1, NOW(), NOW(), 1
);
```

---

## Complete Table Traversal Queries

### 1. **User to Complete Security Posture**

```sql
-- Get complete security overview for a user
SELECT
    u.username,
    c.name as container_name,
    c.url as container_url,
    t.topic,
    cs.security_posture,
    cs.total_findings,
    cs.last_tested_at,
    COUNT(DISTINCT s.id) as total_sessions,
    COUNT(DISTINCT f.id) as total_findings_detailed
FROM auth_user u
    JOIN container_container c ON u.id = c.user_id
    JOIN vapt_containersecurity cs ON c.id = cs.container_id
    LEFT JOIN auth_api_app_usertopicmapping t ON c.topic_id = t.id
    LEFT JOIN vapt_orchestrationsession s ON c.id = s.container_id
    LEFT JOIN vapt_securityfinding f ON s.id = f.session_id
WHERE u.username = 'target_user'
GROUP BY u.id, c.id;
```

### 2. **Container to Detailed Vulnerability Analysis**

```sql
-- Traverse from container to all vulnerability details
SELECT
    c.name as container_name,
    di.name as docker_image,
    spec.ram, spec.vcpu,
    f.finding_type,
    f.severity,
    f.title,
    f.affected_url,
    cf.affected_component,
    cf.deployment_impact,
    a.action_command,
    nr.method, nr.status_code
FROM container_container c
    LEFT JOIN container_containerdockermapping cdm ON c.id = cdm.container_id
    LEFT JOIN container_dockerimage di ON cdm.docker_id = di.id
    LEFT JOIN container_containerspecs spec ON c.id = spec.container_id
    LEFT JOIN vapt_orchestrationsession s ON c.id = s.container_id
    LEFT JOIN vapt_securityfinding f ON s.id = f.session_id
    LEFT JOIN vapt_containerfindings cf ON f.id = cf.finding_id
    LEFT JOIN vapt_actionexecution a ON f.action_id = a.id
    LEFT JOIN vapt_networkrequest nr ON a.id = nr.action_id
WHERE c.id = 25
ORDER BY f.severity DESC, f.created_at DESC;
```

### 3. **Topic to Comprehensive Project Security**

```sql
-- Project-wide security analysis
SELECT
    t.topic,
    COUNT(DISTINCT c.id) as total_containers,
    COUNT(DISTINCT s.id) as total_vapt_sessions,
    COUNT(DISTINCT f.id) as total_findings,
    COUNT(CASE WHEN f.severity = 'critical' THEN 1 END) as critical_findings,
    COUNT(CASE WHEN f.severity = 'high' THEN 1 END) as high_findings,
    AVG(cs.security_score) as avg_security_score,
    MAX(s.completed_at) as last_vapt_session
FROM auth_api_app_usertopicmapping t
    LEFT JOIN container_container c ON t.id = c.topic_id
    LEFT JOIN vapt_containersecurity cs ON c.id = cs.container_id
    LEFT JOIN vapt_orchestrationsession s ON c.id = s.container_id
    LEFT JOIN vapt_securityfinding f ON s.id = f.session_id
WHERE t.topic = 'my-project' AND t.is_active = 1
GROUP BY t.id;
```

### 4. **Finding to Complete Context Trace**

```sql
-- Trace finding back to complete context
SELECT
    f.title as finding_title,
    f.severity,
    u.username as discovered_by,
    c.name as container_name,
    c.url as container_url,
    t.topic,
    s.session_name,
    p.plan_title,
    a.action_command,
    url.url as tested_url,
    f.payload_used,
    f.technical_details,
    cf.affected_component,
    nr.request_body,
    nr.response_body
FROM vapt_securityfinding f
    JOIN vapt_orchestrationsession s ON f.session_id = s.id
    JOIN auth_user u ON s.user_id = u.id
    LEFT JOIN container_container c ON s.container_id = c.id
    LEFT JOIN auth_api_app_usertopicmapping t ON s.topic_id = t.id
    LEFT JOIN vapt_urldiscovery url ON f.url_id = url.id
    LEFT JOIN vapt_securityplan p ON f.plan_id = p.id
    LEFT JOIN vapt_actionexecution a ON f.action_id = a.id
    LEFT JOIN vapt_containerfindings cf ON f.id = cf.finding_id
    LEFT JOIN vapt_networkrequest nr ON a.id = nr.action_id
WHERE f.id = 1;
```

---

## Key Integration Benefits

### 1. **Complete Audit Trail**

- Every action traceable from user to container to finding
- Full conversation history preserved
- Network traffic captured and linked

### 2. **Container Security Management**

- Direct integration with existing container infrastructure
- Security posture tracking per container
- Impact analysis on deployment components

### 3. **User and Project Organization**

- Seamless integration with Django user system
- Topic-based project organization
- Multi-user collaboration support

### 4. **Analytics and Reporting**

- Cross-table analytics for security insights
- Performance tracking and optimization
- Compliance and audit reporting

### 5. **Scalable Architecture**

- Django ORM compatibility
- Proper indexing for performance
- Trigger-based automatic updates

This integrated schema provides a complete foundation for VAPT orchestration while maintaining full compatibility with the existing Django infrastructure, enabling powerful cross-system analytics and reporting capabilities.
