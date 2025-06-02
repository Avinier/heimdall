"""
VAPT Database Integration Module - Django Integration
This module provides integration between the run_orchestration function and the Django-integrated VAPT database schema.
It includes practical classes and methods to track all orchestration activities with full Django compatibility.
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import mysql.connector
from mysql.connector import Error

class VAPTDatabaseTracker:
    """
    Database tracker for VAPT orchestration activities.
    Integrates with the run_orchestration function to provide comprehensive tracking
    with full Django database integration.
    """
    
    def __init__(self, db_config: Dict[str, str]):
        """
        Initialize the database tracker.
        
        Args:
            db_config: Database connection configuration
                      {'host': 'localhost', 'database': 'quantumsenses', 'user': 'root', 'password': '...'}
        """
        self.db_config = db_config
        self.connection = None
        self.session_id = None
        self.agent_instances = {}  # Cache agent IDs
        
    def connect(self):
        """Establish database connection."""
        try:
            self.connection = mysql.connector.connect(**self.db_config)
            print("✓ Database connection established")
        except Error as e:
            print(f"✗ Database connection failed: {e}")
            raise
    
    def disconnect(self):
        """Close database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("✓ Database connection closed")
    
    def start_orchestration_session(self, 
                                  session_name: str,
                                  base_url: str, 
                                  user_id: int,
                                  container_id: Optional[int] = None,
                                  topic_id: Optional[int] = None,
                                  config: Dict = None) -> int:
        """
        Start a new VAPT orchestration session with Django integration.
        
        Args:
            session_name: Human-readable session name
            base_url: Target URL for testing
            user_id: Django auth_user ID
            container_id: Optional container ID from container_container table
            topic_id: Optional topic ID from auth_api_app_usertopicmapping table
            config: Configuration dictionary
        
        Returns:
            int: Session ID
        """
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor()
        
        # Parse target hostname
        target_hostname = urlparse(base_url).netloc
        
        # If container_id provided but topic_id not, get topic from container
        if container_id and not topic_id:
            cursor.execute("SELECT topic_id FROM container_container WHERE id = %s", (container_id,))
            result = cursor.fetchone()
            if result:
                topic_id = result[0]
        
        # Prepare configuration JSON
        config_json = json.dumps(config) if config else None
        
        query = """
        INSERT INTO vapt_orchestrationsession (
            session_name, base_url, target_hostname, user_id, container_id, topic_id,
            expand_scope, max_iterations, keep_messages, status, started_at,
            configuration, created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            session_name, base_url, target_hostname, user_id, container_id, topic_id,
            config.get('expand_scope', True) if config else True,
            config.get('max_iterations', 10) if config else 10,
            config.get('keep_messages', 12) if config else 12,
            'initializing', datetime.now(), config_json,
            datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        
        self.session_id = cursor.lastrowid
        print(f"✓ Started VAPT session {self.session_id}: {session_name}")
        
        # Initialize container security tracking if container provided
        if container_id:
            self._initialize_container_security(container_id, user_id, topic_id)
        
        cursor.close()
        return self.session_id
    
    def _initialize_container_security(self, container_id: int, user_id: int, topic_id: Optional[int] = None):
        """Initialize or update container security tracking."""
        cursor = self.connection.cursor()
        
        query = """
        INSERT INTO vapt_containersecurity (
            container_id, user_id, topic_id, last_vapt_session_id,
            total_vapt_sessions, last_tested_at, created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            last_vapt_session_id = %s,
            total_vapt_sessions = total_vapt_sessions + 1,
            last_tested_at = %s,
            updated_at = %s
        """
        
        now = datetime.now()
        values = (
            container_id, user_id, topic_id, self.session_id,
            1, now, now, now, True,
            # ON DUPLICATE KEY UPDATE values
            self.session_id, now, now
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()
    
    def register_agent(self, agent_type: str, agent_config: Dict, status: str = 'success') -> int:
        """
        Register an agent instance for the current session.
        
        Args:
            agent_type: 'planner', 'actioner', or 'context_manager'
            agent_config: Agent configuration dictionary
            status: 'success' or 'failed'
        
        Returns:
            int: Agent instance ID
        """
        cursor = self.connection.cursor()
        
        query = """
        INSERT INTO vapt_agentinstance (
            session_id, agent_type, agent_config, initialization_status,
            total_calls, total_tokens_used, created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            self.session_id, agent_type, json.dumps(agent_config), status,
            0, 0, datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        
        agent_id = cursor.lastrowid
        self.agent_instances[agent_type] = agent_id
        
        print(f"✓ Registered {agent_type} agent (ID: {agent_id})")
        
        cursor.close()
        return agent_id
    
    def track_url_discovery(self, 
                           url: str, 
                           discovery_source: str,
                           discovery_iteration: int,
                           parent_url_id: Optional[int] = None) -> int:
        """
        Track a discovered URL with Django integration.
        
        Args:
            url: The discovered URL
            discovery_source: How it was discovered ('initial', 'page_extraction', etc.)
            discovery_iteration: Which iteration discovered it
            parent_url_id: ID of the URL that led to this discovery
        
        Returns:
            int: URL discovery ID
        """
        cursor = self.connection.cursor()
        
        # Generate URL hash for deduplication
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        # Determine URL type
        url_type = 'page'
        if '/api/' in url:
            url_type = 'api'
        elif any(ext in url for ext in ['.js', '.css', '.png', '.jpg', '.ico']):
            url_type = 'asset'
        elif 'websocket' in url or 'ws://' in url or 'wss://' in url:
            url_type = 'websocket'
        
        query = """
        INSERT INTO vapt_urldiscovery (
            session_id, url, url_hash, discovery_source, discovery_iteration,
            parent_url_id, url_type, status, created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            self.session_id, url, url_hash, discovery_source, discovery_iteration,
            parent_url_id, url_type, 'discovered', datetime.now(), datetime.now(), True
        )
        
        try:
            cursor.execute(query, values)
            self.connection.commit()
            url_id = cursor.lastrowid
            print(f"✓ Tracked URL discovery: {url} (ID: {url_id})")
            
        except mysql.connector.IntegrityError:
            # URL already exists, get existing ID
            select_query = "SELECT id FROM vapt_urldiscovery WHERE session_id = %s AND url_hash = %s"
            cursor.execute(select_query, (self.session_id, url_hash))
            url_id = cursor.fetchone()[0]
            print(f"↻ URL already tracked: {url} (ID: {url_id})")
        
        cursor.close()
        return url_id
    
    def store_page_data(self, 
                       url_id: int, 
                       raw_page_data: str, 
                       summarized_data: str,
                       extraction_stats: Dict) -> None:
        """
        Store extracted page data with Django integration.
        
        Args:
            url_id: URL discovery ID
            raw_page_data: Full extracted page data
            summarized_data: Summarized page data
            extraction_stats: Statistics from PageDataExtractor
        """
        cursor = self.connection.cursor()
        
        query = """
        INSERT INTO vapt_pagedata (
            url_id, raw_page_data, summarized_page_data, links_count,
            forms_count, api_endpoints_count, sensitive_strings_count,
            security_headers_count, cookies_count, hidden_endpoints_count,
            technology_stack, extraction_metadata, created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            url_id, raw_page_data, summarized_data,
            extraction_stats.get('links_count', 0),
            extraction_stats.get('forms_count', 0),
            extraction_stats.get('api_endpoints_count', 0),
            extraction_stats.get('sensitive_strings_count', 0),
            extraction_stats.get('security_headers_count', 0),
            extraction_stats.get('cookies_count', 0),
            extraction_stats.get('hidden_endpoints_count', 0),
            json.dumps(extraction_stats.get('technology_stack', {})),
            json.dumps(extraction_stats.get('metadata', {})),
            datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        
        print(f"✓ Stored page data for URL ID {url_id}")
        cursor.close()
    
    def create_security_plan(self, 
                           url_id: int, 
                           plan: Dict, 
                           plan_order: int,
                           llm_metadata: Dict = None) -> int:
        """
        Create a security test plan record with Django integration.
        
        Args:
            url_id: URL discovery ID
            plan: Plan dictionary with title and description
            plan_order: Order of plan generation
            llm_metadata: LLM generation metadata
        
        Returns:
            int: Security plan ID
        """
        cursor = self.connection.cursor()
        
        # Determine plan type from title/description
        plan_type = 'general'
        title_lower = plan.get('title', '').lower()
        desc_lower = plan.get('description', '').lower()
        
        type_mapping = {
            'sql': 'sql_injection',
            'xss': 'xss',
            'auth': 'authentication',
            'login': 'authentication',
            'authorization': 'authorization',
            'csrf': 'csrf',
            'upload': 'file_upload',
            'traversal': 'directory_traversal',
            'api': 'api_security',
            'session': 'session_management',
            'disclosure': 'information_disclosure'
        }
        
        for keyword, p_type in type_mapping.items():
            if keyword in title_lower or keyword in desc_lower:
                plan_type = p_type
                break
        
        # Determine priority
        priority = 'medium'
        if any(word in title_lower for word in ['critical', 'severe', 'injection']):
            priority = 'critical'
        elif any(word in title_lower for word in ['high', 'important', 'bypass']):
            priority = 'high'
        elif any(word in title_lower for word in ['low', 'minor', 'info']):
            priority = 'low'
        
        query = """
        INSERT INTO vapt_securityplan (
            url_id, planner_agent_id, plan_title, plan_description,
            plan_type, priority, plan_order, status,
            llm_generation_metadata, created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            url_id, self.agent_instances.get('planner'),
            plan.get('title', 'Untitled Plan'),
            plan.get('description', 'No description'),
            plan_type, priority, plan_order, 'generated',
            json.dumps(llm_metadata) if llm_metadata else None,
            datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        
        plan_id = cursor.lastrowid
        print(f"✓ Created security plan: {plan.get('title')} (ID: {plan_id})")
        
        cursor.close()
        return plan_id
    
    def track_action_execution(self, 
                             plan_id: int,
                             iteration_number: int,
                             action_type: str,
                             action_command: str,
                             discussion: str = None,
                             action_output: str = None,
                             execution_status: str = 'success') -> int:
        """
        Track an action execution with Django integration.
        
        Args:
            plan_id: Security plan ID
            iteration_number: Current iteration number
            action_type: Type of action (goto, click, fill, etc.)
            action_command: The actual command executed
            discussion: Actioner's reasoning
            action_output: Output from action execution
            execution_status: 'success', 'failed', or 'error'
        
        Returns:
            int: Action execution ID
        """
        cursor = self.connection.cursor()
        
        # Extract target element and other details from command
        target_element = None
        input_value = None
        action_url = None
        
        if 'goto(' in action_command:
            # Extract URL from goto command
            import re
            url_match = re.search(r'goto\s*\(\s*page\s*,\s*["\']([^"\']*)["\']', action_command)
            if url_match:
                action_url = url_match.group(1)
        
        elif 'click(' in action_command:
            # Extract selector from click command
            import re
            selector_match = re.search(r'click\s*\(\s*page\s*,\s*["\']([^"\']*)["\']', action_command)
            if selector_match:
                target_element = selector_match.group(1)
        
        elif 'fill(' in action_command:
            # Extract selector and value from fill command
            import re
            fill_match = re.search(r'fill\s*\(\s*page\s*,\s*["\']([^"\']*)["\'].*["\']([^"\']*)["\']', action_command)
            if fill_match:
                target_element = fill_match.group(1)
                input_value = fill_match.group(2)
        
        query = """
        INSERT INTO vapt_actionexecution (
            plan_id, actioner_agent_id, iteration_number, action_type,
            action_command, action_discussion, target_element, input_value,
            action_url, execution_status, action_output, executed_at, 
            created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            plan_id, self.agent_instances.get('actioner'), iteration_number, action_type,
            action_command, discussion, target_element, input_value,
            action_url, execution_status, action_output, datetime.now(), 
            datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        
        action_id = cursor.lastrowid
        print(f"✓ Tracked action execution: {action_type} (ID: {action_id})")
        
        cursor.close()
        return action_id
    
    def store_conversation_message(self, 
                                 plan_id: int,
                                 message_order: int,
                                 role: str,
                                 content: str,
                                 message_type: str = 'action_discussion',
                                 related_action_id: Optional[int] = None) -> None:
        """
        Store a conversation message with Django integration.
        
        Args:
            plan_id: Security plan ID
            message_order: Order of message in conversation
            role: 'user', 'assistant', or 'system'
            content: Message content
            message_type: Type of message
            related_action_id: Related action ID if applicable
        """
        cursor = self.connection.cursor()
        
        query = """
        INSERT INTO vapt_conversationhistory (
            plan_id, message_order, role, content, message_type,
            related_action_id, token_count, is_summarized, 
            created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        # Estimate token count (rough approximation)
        token_count = len(content.split()) * 1.3  # Approximate tokens
        
        values = (
            plan_id, message_order, role, content, message_type,
            related_action_id, int(token_count), False, 
            datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()
    
    def record_security_finding(self, 
                              finding_type: str,
                              severity: str,
                              title: str,
                              description: str,
                              url_id: Optional[int] = None,
                              plan_id: Optional[int] = None,
                              action_id: Optional[int] = None,
                              technical_details: str = None,
                              payload_used: str = None) -> int:
        """
        Record a security finding with Django integration.
        
        Args:
            finding_type: Type of finding (sql_injection, xss, etc.)
            severity: Severity level (info, low, medium, high, critical)
            title: Finding title
            description: Finding description
            url_id: Related URL ID
            plan_id: Related plan ID
            action_id: Related action ID
            technical_details: Technical details
            payload_used: Payload that triggered the finding
        
        Returns:
            int: Security finding ID
        """
        cursor = self.connection.cursor()
        
        # Get container_id from session
        cursor.execute("SELECT container_id FROM vapt_orchestrationsession WHERE id = %s", (self.session_id,))
        result = cursor.fetchone()
        container_id = result[0] if result else None
        
        query = """
        INSERT INTO vapt_securityfinding (
            session_id, url_id, plan_id, action_id, container_id, finding_type,
            severity, title, description, technical_details,
            payload_used, detection_method, confidence, status,
            created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            self.session_id, url_id, plan_id, action_id, container_id, finding_type,
            severity, title, description, technical_details,
            payload_used, 'conversation_analysis', 'medium', 'new',
            datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        
        finding_id = cursor.lastrowid
        print(f"🔍 Recorded security finding: {title} (ID: {finding_id}, Severity: {severity})")
        
        # If container_id exists, link to container components
        if container_id:
            self._link_finding_to_container_components(finding_id, container_id, finding_type, severity)
        
        cursor.close()
        return finding_id
    
    def _link_finding_to_container_components(self, finding_id: int, container_id: int, 
                                           finding_type: str, severity: str) -> None:
        """Link finding to specific container components."""
        cursor = self.connection.cursor()
        
        # Determine affected component based on finding type
        component_mapping = {
            'sql_injection': 'application',
            'xss': 'application',
            'authentication': 'application',
            'authorization': 'application',
            'api_security': 'application',
            'file_upload': 'application',
            'directory_traversal': 'application',
            'session_management': 'application',
            'information_disclosure': 'configuration',
            'csrf': 'application'
        }
        
        affected_component = component_mapping.get(finding_type, 'application')
        
        # Get container components
        cursor.execute("""
            SELECT di.id, cs.id, ce.id, pm.id
            FROM container_container c
            LEFT JOIN container_containerdockermapping cdm ON c.id = cdm.container_id
            LEFT JOIN container_dockerimage di ON cdm.docker_id = di.id
            LEFT JOIN container_containerspecs cs ON c.id = cs.container_id
            LEFT JOIN container_containerenv ce ON c.id = ce.container_id
            LEFT JOIN container_portmappingcontainer pm ON c.id = pm.container_id
            WHERE c.id = %s AND c.is_active = 1
            LIMIT 1
        """, (container_id,))
        
        result = cursor.fetchone()
        if result:
            docker_image_id, specs_id, env_id, port_mapping_id = result
            
            query = """
            INSERT INTO vapt_containerfindings (
                finding_id, container_id, docker_image_id, container_specs_id,
                container_env_id, port_mapping_id, affected_component,
                component_details, risk_level, remediation_priority,
                affects_other_containers, deployment_impact,
                created_at, updated_at, is_active
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            # Determine deployment impact
            deployment_impact = 'low'
            if severity in ['critical', 'high']:
                deployment_impact = 'high' if severity == 'critical' else 'medium'
            
            values = (
                finding_id, container_id, docker_image_id, specs_id,
                env_id, port_mapping_id, affected_component,
                f'{finding_type} vulnerability in {affected_component}',
                severity, 'high' if severity in ['critical', 'high'] else 'medium',
                False, deployment_impact,
                datetime.now(), datetime.now(), True
            )
            
            cursor.execute(query, values)
            self.connection.commit()
            
        cursor.close()
    
    def track_token_usage(self, 
                         agent_type: str,
                         operation_type: str,
                         model_used: str,
                         api_provider: str,
                         total_tokens: int,
                         response_time: float = None) -> None:
        """
        Track token usage for analysis with Django integration.
        
        Args:
            agent_type: Type of agent ('planner', 'actioner', 'context_manager')
            operation_type: Type of operation
            model_used: Model name
            api_provider: API provider (gemini, fireworks, etc.)
            total_tokens: Total tokens used
            response_time: Response time in seconds
        """
        cursor = self.connection.cursor()
        
        query = """
        INSERT INTO vapt_tokenusage (
            session_id, agent_id, operation_type, model_used,
            api_provider, total_tokens, response_time, timestamp, 
            created_at, updated_at, is_active
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            self.session_id, self.agent_instances.get(agent_type),
            operation_type, model_used, api_provider, total_tokens,
            response_time, datetime.now(), datetime.now(), datetime.now(), True
        )
        
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()
    
    def update_session_status(self, status: str, final_summary: str = None) -> None:
        """
        Update session status with Django integration.
        
        Args:
            status: New status ('running', 'completed', 'failed', 'paused')
            final_summary: Final summary if completed
        """
        cursor = self.connection.cursor()
        
        if status == 'completed':
            query = """
            UPDATE vapt_orchestrationsession 
            SET status = %s, completed_at = %s, final_summary = %s, updated_at = %s
            WHERE id = %s
            """
            values = (status, datetime.now(), final_summary, datetime.now(), self.session_id)
        else:
            query = """
            UPDATE vapt_orchestrationsession 
            SET status = %s, updated_at = %s
            WHERE id = %s
            """
            values = (status, datetime.now(), self.session_id)
        
        cursor.execute(query, values)
        self.connection.commit()
        
        print(f"✓ Updated session status to: {status}")
        cursor.close()
    
    def get_session_summary(self) -> Dict[str, Any]:
        """
        Get a comprehensive summary of the session with Django integration.
        
        Returns:
            Dict containing session statistics and findings
        """
        cursor = self.connection.cursor(dictionary=True)
        
        # Get session overview
        query = "SELECT * FROM v_vapt_session_overview WHERE session_id = %s"
        cursor.execute(query, (self.session_id,))
        session_overview = cursor.fetchone()
        
        # Get findings summary  
        query = "SELECT * FROM v_vapt_findings_analysis WHERE session_id = %s"
        cursor.execute(query, (self.session_id,))
        findings_summary = cursor.fetchall()
        
        # Get container security info if available
        container_security = None
        if session_overview and session_overview.get('container_name'):
            query = "SELECT * FROM v_container_security_dashboard WHERE container_id = %s"
            cursor.execute(query, (session_overview['container_id'],))
            container_security = cursor.fetchone()
        
        # Get recent actions
        query = """
        SELECT p.plan_title, a.action_type, a.action_command, a.executed_at
        FROM vapt_actionexecution a
        JOIN vapt_securityplan p ON a.plan_id = p.id
        JOIN vapt_urldiscovery u ON p.url_id = u.id
        WHERE u.session_id = %s AND a.is_active = 1
        ORDER BY a.executed_at DESC
        LIMIT 10
        """
        cursor.execute(query, (self.session_id,))
        recent_actions = cursor.fetchall()
        
        cursor.close()
        
        return {
            'session_overview': session_overview,
            'findings_summary': findings_summary,
            'container_security': container_security,
            'recent_actions': recent_actions
        }
    
    def get_container_security_posture(self, container_id: int) -> Dict[str, Any]:
        """
        Get comprehensive security posture for a specific container.
        
        Args:
            container_id: Container ID
            
        Returns:
            Dict containing container security information
        """
        cursor = self.connection.cursor(dictionary=True)
        
        query = "SELECT * FROM v_container_security_dashboard WHERE container_id = %s"
        cursor.execute(query, (container_id,))
        container_info = cursor.fetchone()
        
        # Get all VAPT sessions for this container
        query = """
        SELECT s.id, s.session_name, s.started_at, s.completed_at, s.status,
               s.total_findings, s.total_actions_performed
        FROM vapt_orchestrationsession s
        WHERE s.container_id = %s AND s.is_active = 1
        ORDER BY s.started_at DESC
        """
        cursor.execute(query, (container_id,))
        sessions = cursor.fetchall()
        
        # Get all findings for this container
        query = """
        SELECT f.finding_type, f.severity, f.title, f.status, f.created_at,
               cf.affected_component, cf.deployment_impact
        FROM vapt_securityfinding f
        LEFT JOIN vapt_containerfindings cf ON f.id = cf.finding_id
        WHERE f.container_id = %s AND f.is_active = 1
        ORDER BY f.created_at DESC
        """
        cursor.execute(query, (container_id,))
        findings = cursor.fetchall()
        
        cursor.close()
        
        return {
            'container_info': container_info,
            'vapt_sessions': sessions,
            'security_findings': findings
        }


# Enhanced integration for Django environment
class DjangoVAPTIntegration:
    """
    Django-specific VAPT integration with model-like interface.
    """
    
    def __init__(self, db_config: Dict[str, str]):
        self.tracker = VAPTDatabaseTracker(db_config)
    
    def start_vapt_for_container(self, container_id: int, user_id: int, 
                               base_url: str = None, config: Dict = None) -> int:
        """
        Start VAPT session for a specific container with automatic URL detection.
        
        Args:
            container_id: Container ID from container_container table
            user_id: User ID from auth_user table
            base_url: Optional override for container URL
            config: VAPT configuration
            
        Returns:
            int: Session ID
        """
        self.tracker.connect()
        
        # Get container details
        cursor = self.tracker.connection.cursor(dictionary=True)
        query = """
        SELECT c.name, c.url, c.topic_id, u.username, t.topic
        FROM container_container c
        JOIN auth_user u ON c.user_id = u.id
        LEFT JOIN auth_api_app_usertopicmapping t ON c.topic_id = t.id
        WHERE c.id = %s AND c.is_active = 1
        """
        cursor.execute(query, (container_id,))
        container_info = cursor.fetchone()
        cursor.close()
        
        if not container_info:
            raise ValueError(f"Container {container_id} not found or inactive")
        
        # Use container URL if base_url not provided
        target_url = base_url or container_info['url']
        
        # Generate session name
        session_name = f"VAPT-{container_info['name']}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Start session
        session_id = self.tracker.start_orchestration_session(
            session_name=session_name,
            base_url=target_url,
            user_id=user_id,
            container_id=container_id,
            topic_id=container_info['topic_id'],
            config=config
        )
        
        print(f"✓ Started VAPT session for container '{container_info['name']}' (Topic: {container_info.get('topic', 'None')})")
        
        return session_id
    
    def get_user_containers_with_security_status(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all containers for a user with their security status.
        
        Args:
            user_id: User ID
            
        Returns:
            List of containers with security information
        """
        if not self.tracker.connection:
            self.tracker.connect()
            
        cursor = self.tracker.connection.cursor(dictionary=True)
        
        query = """
        SELECT 
            c.id, c.name, c.url, c.ip_address, c.running,
            t.topic,
            cs.security_posture, cs.total_findings, cs.last_tested_at,
            cs.critical_findings, cs.high_findings,
            COUNT(DISTINCT s.id) as active_sessions
        FROM container_container c
        LEFT JOIN auth_api_app_usertopicmapping t ON c.topic_id = t.id
        LEFT JOIN vapt_containersecurity cs ON c.id = cs.container_id
        LEFT JOIN vapt_orchestrationsession s ON c.id = s.container_id AND s.status = 'running'
        WHERE c.user_id = %s AND c.is_active = 1
        GROUP BY c.id
        ORDER BY c.updated_at DESC
        """
        
        cursor.execute(query, (user_id,))
        containers = cursor.fetchall()
        cursor.close()
        
        return containers
    
    def get_topic_security_overview(self, topic_id: int) -> Dict[str, Any]:
        """
        Get security overview for an entire topic/project.
        
        Args:
            topic_id: Topic ID
            
        Returns:
            Dict containing project security overview
        """
        if not self.tracker.connection:
            self.tracker.connect()
            
        cursor = self.tracker.connection.cursor(dictionary=True)
        
        # Get topic info with aggregated security data
        query = """
        SELECT 
            t.topic,
            t.is_deployed,
            COUNT(DISTINCT c.id) as total_containers,
            COUNT(DISTINCT s.id) as total_vapt_sessions,
            COUNT(DISTINCT f.id) as total_findings,
            COUNT(CASE WHEN f.severity = 'critical' THEN 1 END) as critical_findings,
            COUNT(CASE WHEN f.severity = 'high' THEN 1 END) as high_findings,
            COUNT(CASE WHEN f.severity = 'medium' THEN 1 END) as medium_findings,
            COUNT(CASE WHEN f.severity = 'low' THEN 1 END) as low_findings,
            MAX(s.completed_at) as last_vapt_session,
            AVG(cs.security_score) as avg_security_score
        FROM auth_api_app_usertopicmapping t
        LEFT JOIN container_container c ON t.id = c.topic_id AND c.is_active = 1
        LEFT JOIN vapt_containersecurity cs ON c.id = cs.container_id
        LEFT JOIN vapt_orchestrationsession s ON c.id = s.container_id
        LEFT JOIN vapt_securityfinding f ON s.id = f.session_id AND f.is_active = 1
        WHERE t.id = %s
        GROUP BY t.id
        """
        
        cursor.execute(query, (topic_id,))
        overview = cursor.fetchone()
        
        # Get detailed container breakdown
        query = """
        SELECT 
            c.id, c.name, c.url, c.running,
            cs.security_posture, cs.total_findings, cs.last_tested_at
        FROM container_container c
        LEFT JOIN vapt_containersecurity cs ON c.id = cs.container_id
        WHERE c.topic_id = %s AND c.is_active = 1
        ORDER BY cs.last_tested_at DESC
        """
        
        cursor.execute(query, (topic_id,))
        containers = cursor.fetchall()
        
        cursor.close()
        
        return {
            'topic_overview': overview,
            'containers': containers
        }


# Usage example with Django integration
if __name__ == "__main__":
    # Database configuration
    db_config = {
        'host': 'localhost',
        'database': 'quantumsenses',
        'user': 'root',
        'password': 'your_password_here'
    }
    
    # Create Django integration instance
    django_integration = DjangoVAPTIntegration(db_config)
    
    try:
        # Start VAPT for a specific container
        session_id = django_integration.start_vapt_for_container(
            container_id=25,  # Existing container
            user_id=1,        # Django user
            config={
                'expand_scope': True,
                'max_iterations': 10,
                'keep_messages': 12
            }
        )
        
        # Get user's containers with security status
        user_containers = django_integration.get_user_containers_with_security_status(user_id=1)
        print(f"User has {len(user_containers)} containers")
        
        # Get topic security overview
        topic_overview = django_integration.get_topic_security_overview(topic_id=15)
        print(f"Topic overview: {topic_overview['topic_overview']['topic']}")
        
        print("Django VAPT integration completed successfully!")
        
    except Exception as e:
        print(f"Django VAPT integration failed: {e}")
    
    finally:
        django_integration.tracker.disconnect() 