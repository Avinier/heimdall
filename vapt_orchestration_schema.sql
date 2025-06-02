-- VAPT Orchestration Database Schema - Django Integration
-- This schema integrates with the existing Django quantumsenses database
-- Following Django conventions and proper foreign key relationships

-- =====================================================
-- VAPT ORCHESTRATION CORE TABLES
-- =====================================================

-- Main VAPT orchestration sessions
DROP TABLE IF EXISTS `vapt_orchestrationsession`;
CREATE TABLE `vapt_orchestrationsession` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_name` varchar(200) NOT NULL,
  `base_url` varchar(500) NOT NULL,
  `target_hostname` varchar(200) NOT NULL,
  `user_id` int NOT NULL,  -- FK to auth_user
  `container_id` bigint DEFAULT NULL,  -- FK to container_container
  `topic_id` bigint DEFAULT NULL,  -- FK to auth_api_app_usertopicmapping
  `expand_scope` tinyint(1) DEFAULT 1,
  `max_iterations` int DEFAULT 10,
--   `keep_messages` int DEFAULT 12,
  `status` varchar(20) DEFAULT 'initializing',
  `started_at` datetime(6) NOT NULL,
  `completed_at` datetime(6) DEFAULT NULL,
  `total_urls_discovered` int DEFAULT 0,
  `total_urls_tested` int DEFAULT 0,
  `total_plans_executed` int DEFAULT 0,
  `total_actions_performed` int DEFAULT 0,
  `total_findings` int DEFAULT 0,
  `total_tokens_used` bigint DEFAULT 0,
  `configuration` json DEFAULT NULL,
  `final_summary` longtext DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_orchestrationsession_user_id_idx` (`user_id`),
  KEY `vapt_orchestrationsession_container_id_idx` (`container_id`),
  KEY `vapt_orchestrationsession_topic_id_idx` (`topic_id`),
  KEY `vapt_orchestrationsession_status_idx` (`status`),
  KEY `vapt_orchestrationsession_started_at_idx` (`started_at`),
  CONSTRAINT `vapt_orchestrationsession_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `vapt_orchestrationsession_container_id_fk` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`),
  CONSTRAINT `vapt_orchestrationsession_topic_id_fk` FOREIGN KEY (`topic_id`) REFERENCES `auth_api_app_usertopicmapping` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Agents used in orchestration
DROP TABLE IF EXISTS `vapt_agentinstance`;
CREATE TABLE `vapt_agentinstance` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `agent_type` varchar(20) NOT NULL,
  `agent_config` json NOT NULL,
  `initialization_status` varchar(10) NOT NULL DEFAULT ' success',
  `initialization_error` text DEFAULT NULL,
  `total_calls` int DEFAULT 0,
  `total_tokens_used` bigint DEFAULT 0,
  `avg_response_time` decimal(10,3) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_agentinstance_session_id_idx` (`session_id`),
  KEY `vapt_agentinstance_agent_type_idx` (`agent_type`),
  CONSTRAINT `vapt_agentinstance_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- URL DISCOVERY AND TESTING TRACKING
-- =====================================================

-- URLs discovered and processed during orchestration
DROP TABLE IF EXISTS `vapt_urldiscovery`;
CREATE TABLE `vapt_urldiscovery` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `url` varchar(2000) NOT NULL,
  `url_hash` varchar(64) NOT NULL,
  `discovery_source` varchar(20) NOT NULL DEFAULT 'initial',
  `discovery_iteration` int NOT NULL,
  `parent_url_id` bigint DEFAULT NULL,
  `url_type` varchar(15) DEFAULT 'page',
  `status` varchar(15) DEFAULT 'discovered',
  `http_status_code` int DEFAULT NULL,
  `response_size` bigint DEFAULT NULL,
  `page_title` varchar(500) DEFAULT NULL,
  `content_type` varchar(100) DEFAULT NULL,
  `processing_started_at` datetime(6) DEFAULT NULL,
  `processing_completed_at` datetime(6) DEFAULT NULL,
  `processing_duration` decimal(10,3) DEFAULT NULL,
  `error_message` text DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `vapt_urldiscovery_session_url_hash_uniq` (`session_id`, `url_hash`),
  KEY `vapt_urldiscovery_status_idx` (`status`),
  KEY `vapt_urldiscovery_discovery_source_idx` (`discovery_source`),
  KEY `vapt_urldiscovery_parent_url_id_idx` (`parent_url_id`),
  CONSTRAINT `vapt_urldiscovery_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_urldiscovery_parent_url_id_fk` FOREIGN KEY (`parent_url_id`) REFERENCES `vapt_urldiscovery` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Page data extracted from each URL
DROP TABLE IF EXISTS `vapt_pagedata`;
CREATE TABLE `vapt_pagedata` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `url_id` bigint NOT NULL,
  `raw_page_data` longtext DEFAULT NULL,
  `summarized_page_data` text DEFAULT NULL,
  `html_content_summary` text DEFAULT NULL,
  `links_count` int DEFAULT 0,
  `forms_count` int DEFAULT 0,
  `api_endpoints_count` int DEFAULT 0,
  `sensitive_strings_count` int DEFAULT 0,
  `security_headers_count` int DEFAULT 0,
  `cookies_count` int DEFAULT 0,
  `hidden_endpoints_count` int DEFAULT 0,
  `technology_stack` json DEFAULT NULL,
  `extraction_metadata` json DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `vapt_pagedata_url_id_uniq` (`url_id`),
  CONSTRAINT `vapt_pagedata_url_id_fk` FOREIGN KEY (`url_id`) REFERENCES `vapt_urldiscovery` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- SECURITY PLAN GENERATION AND EXECUTION
-- =====================================================

-- Security test plans generated by PlannerAgent
DROP TABLE IF EXISTS `vapt_securityplan`;
CREATE TABLE `vapt_securityplan` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `url_id` bigint NOT NULL,
  `planner_agent_id` bigint NOT NULL,
  `plan_title` varchar(500) NOT NULL,
  `plan_description` text NOT NULL,
  `plan_type` varchar(25) DEFAULT 'general',
  `priority` varchar(10) DEFAULT 'medium',
  `estimated_actions` int DEFAULT NULL,
  `plan_order` int NOT NULL,
  `status` varchar(15) DEFAULT 'generated',
  `execution_started_at` datetime(6) DEFAULT NULL,
  `execution_completed_at` datetime(6) DEFAULT NULL,
  `execution_duration` decimal(10,3) DEFAULT NULL,
  `total_iterations` int DEFAULT 0,
  `total_actions_performed` int DEFAULT 0,
  `plan_findings_count` int DEFAULT 0,
  `llm_generation_metadata` json DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_securityplan_url_id_idx` (`url_id`),
  KEY `vapt_securityplan_planner_agent_id_idx` (`planner_agent_id`),
  KEY `vapt_securityplan_status_idx` (`status`),
  KEY `vapt_securityplan_plan_type_idx` (`plan_type`),
  KEY `vapt_securityplan_plan_order_idx` (`plan_order`),
  CONSTRAINT `vapt_securityplan_url_id_fk` FOREIGN KEY (`url_id`) REFERENCES `vapt_urldiscovery` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_securityplan_planner_agent_id_fk` FOREIGN KEY (`planner_agent_id`) REFERENCES `vapt_agentinstance` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- ACTION EXECUTION AND ITERATION TRACKING
-- =====================================================

-- Individual actions performed by ActionerAgent
DROP TABLE IF EXISTS `vapt_actionexecution`;
CREATE TABLE `vapt_actionexecution` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `plan_id` bigint NOT NULL,
  `actioner_agent_id` bigint NOT NULL,
  `iteration_number` int NOT NULL,
  `action_type` varchar(25) NOT NULL,
  `action_command` text NOT NULL,
  `action_discussion` text DEFAULT NULL,
  `target_element` varchar(500) DEFAULT NULL,
  `input_value` text DEFAULT NULL,
  `action_url` varchar(2000) DEFAULT NULL,
  `execution_status` varchar(15) DEFAULT 'pending',
  `action_output` text DEFAULT NULL,
  `action_result_summary` text DEFAULT NULL,
  `execution_duration` decimal(10,3) DEFAULT NULL,
  `error_message` text DEFAULT NULL,
  `network_activity` text DEFAULT NULL,
  `browser_state` json DEFAULT NULL,
  `security_implications` text DEFAULT NULL,
  `llm_generation_metadata` json DEFAULT NULL,
  `executed_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_actionexecution_plan_id_idx` (`plan_id`),
  KEY `vapt_actionexecution_actioner_agent_id_idx` (`actioner_agent_id`),
  KEY `vapt_actionexecution_iteration_number_idx` (`iteration_number`),
  KEY `vapt_actionexecution_action_type_idx` (`action_type`),
  KEY `vapt_actionexecution_execution_status_idx` (`execution_status`),
  CONSTRAINT `vapt_actionexecution_plan_id_fk` FOREIGN KEY (`plan_id`) REFERENCES `vapt_securityplan` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_actionexecution_actioner_agent_id_fk` FOREIGN KEY (`actioner_agent_id`) REFERENCES `vapt_agentinstance` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Conversation history for each plan execution
DROP TABLE IF EXISTS `vapt_conversationhistory`;
CREATE TABLE `vapt_conversationhistory` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `plan_id` bigint NOT NULL,
  `message_order` int NOT NULL,
  `role` varchar(15) NOT NULL,
  `content` longtext NOT NULL,
  `message_type` varchar(20) DEFAULT 'action_discussion',
  `related_action_id` bigint DEFAULT NULL,
  `token_count` int DEFAULT NULL,
  `is_summarized` tinyint(1) DEFAULT 0,
  `original_message_ids` json DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_conversationhistory_plan_id_idx` (`plan_id`),
  KEY `vapt_conversationhistory_message_order_idx` (`message_order`),
  KEY `vapt_conversationhistory_message_type_idx` (`message_type`),
  KEY `vapt_conversationhistory_related_action_id_idx` (`related_action_id`),
  CONSTRAINT `vapt_conversationhistory_plan_id_fk` FOREIGN KEY (`plan_id`) REFERENCES `vapt_securityplan` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_conversationhistory_related_action_id_fk` FOREIGN KEY (`related_action_id`) REFERENCES `vapt_actionexecution` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- SECURITY FINDINGS AND VULNERABILITIES
-- =====================================================

-- Security findings detected during testing
DROP TABLE IF EXISTS `vapt_securityfinding`;
CREATE TABLE `vapt_securityfinding` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `url_id` bigint DEFAULT NULL,
  `plan_id` bigint DEFAULT NULL,
  `action_id` bigint DEFAULT NULL,
  `container_id` bigint DEFAULT NULL,  -- Direct link to tested container
  `finding_type` varchar(30) NOT NULL,
  `severity` varchar(10) NOT NULL,
  `title` varchar(500) NOT NULL,
  `description` text NOT NULL,
  `technical_details` text DEFAULT NULL,
  `proof_of_concept` text DEFAULT NULL,
  `affected_url` varchar(2000) DEFAULT NULL,
  `affected_parameter` varchar(200) DEFAULT NULL,
  `payload_used` text DEFAULT NULL,
  `response_evidence` text DEFAULT NULL,
  `cwe_id` varchar(20) DEFAULT NULL,
  `cvss_score` decimal(3,1) DEFAULT NULL,
  `remediation` text DEFAULT NULL,
  `references` text DEFAULT NULL,
  `detection_method` varchar(25) DEFAULT 'conversation_analysis',
  `confidence` varchar(10) DEFAULT 'medium',
  `false_positive` tinyint(1) DEFAULT 0,
  `verified` tinyint(1) DEFAULT 0,
  `verified_by` int DEFAULT NULL,  -- FK to auth_user
  `verified_at` datetime(6) DEFAULT NULL,
  `status` varchar(15) DEFAULT 'new',
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_securityfinding_session_id_idx` (`session_id`),
  KEY `vapt_securityfinding_url_id_idx` (`url_id`),
  KEY `vapt_securityfinding_plan_id_idx` (`plan_id`),
  KEY `vapt_securityfinding_action_id_idx` (`action_id`),
  KEY `vapt_securityfinding_container_id_idx` (`container_id`),
  KEY `vapt_securityfinding_finding_type_idx` (`finding_type`),
  KEY `vapt_securityfinding_severity_idx` (`severity`),
  KEY `vapt_securityfinding_status_idx` (`status`),
  KEY `vapt_securityfinding_verified_by_idx` (`verified_by`),
  CONSTRAINT `vapt_securityfinding_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_securityfinding_url_id_fk` FOREIGN KEY (`url_id`) REFERENCES `vapt_urldiscovery` (`id`),
  CONSTRAINT `vapt_securityfinding_plan_id_fk` FOREIGN KEY (`plan_id`) REFERENCES `vapt_securityplan` (`id`),
  CONSTRAINT `vapt_securityfinding_action_id_fk` FOREIGN KEY (`action_id`) REFERENCES `vapt_actionexecution` (`id`),
  CONSTRAINT `vapt_securityfinding_container_id_fk` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`),
  CONSTRAINT `vapt_securityfinding_verified_by_fk` FOREIGN KEY (`verified_by`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Evidence files and screenshots
DROP TABLE IF EXISTS `vapt_findingevidence`;
CREATE TABLE `vapt_findingevidence` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `finding_id` bigint NOT NULL,
  `evidence_type` varchar(20) NOT NULL,
  `file_path` varchar(500) DEFAULT NULL,
  `file_size` bigint DEFAULT NULL,
  `mime_type` varchar(100) DEFAULT NULL,
  `content` longtext DEFAULT NULL,
  `metadata` json DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_findingevidence_finding_id_idx` (`finding_id`),
  KEY `vapt_findingevidence_evidence_type_idx` (`evidence_type`),
  CONSTRAINT `vapt_findingevidence_finding_id_fk` FOREIGN KEY (`finding_id`) REFERENCES `vapt_securityfinding` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- NETWORK TRAFFIC AND BROWSER MONITORING
-- =====================================================

-- Network requests captured during testing
DROP TABLE IF EXISTS `vapt_networkrequest`;
CREATE TABLE `vapt_networkrequest` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `action_id` bigint DEFAULT NULL,
  `request_id` varchar(100) NOT NULL,
  `url` varchar(2000) NOT NULL,
  `method` varchar(10) NOT NULL,
  `status_code` int DEFAULT NULL,
  `resource_type` varchar(50) DEFAULT NULL,
  `request_headers` json DEFAULT NULL,
  `response_headers` json DEFAULT NULL,
  `request_body` text DEFAULT NULL,
  `response_body` text DEFAULT NULL,
  `request_timestamp` datetime(6) NOT NULL,
  `response_timestamp` datetime(6) DEFAULT NULL,
  `duration` decimal(10,3) DEFAULT NULL,
  `size` bigint DEFAULT NULL,
  `source` varchar(15) DEFAULT 'playwright',
  `security_analysis` text DEFAULT NULL,
  `contains_sensitive_data` tinyint(1) DEFAULT 0,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_networkrequest_session_id_idx` (`session_id`),
  KEY `vapt_networkrequest_action_id_idx` (`action_id`),
  KEY `vapt_networkrequest_method_idx` (`method`),
  KEY `vapt_networkrequest_status_code_idx` (`status_code`),
  KEY `vapt_networkrequest_resource_type_idx` (`resource_type`),
  KEY `vapt_networkrequest_request_timestamp_idx` (`request_timestamp`),
  CONSTRAINT `vapt_networkrequest_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_networkrequest_action_id_fk` FOREIGN KEY (`action_id`) REFERENCES `vapt_actionexecution` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Browser state snapshots
DROP TABLE IF EXISTS `vapt_browsersnapshot`;
CREATE TABLE `vapt_browsersnapshot` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `action_id` bigint DEFAULT NULL,
  `url` varchar(2000) NOT NULL,
  `page_title` varchar(500) DEFAULT NULL,
  `html_content` longtext DEFAULT NULL,
  `cookies` json DEFAULT NULL,
  `local_storage` json DEFAULT NULL,
  `session_storage` json DEFAULT NULL,
  `console_logs` text DEFAULT NULL,
  `console_errors` text DEFAULT NULL,
  `screenshot_path` varchar(500) DEFAULT NULL,
  `viewport_size` json DEFAULT NULL,
  `timestamp` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_browsersnapshot_session_id_idx` (`session_id`),
  KEY `vapt_browsersnapshot_action_id_idx` (`action_id`),
  KEY `vapt_browsersnapshot_timestamp_idx` (`timestamp`),
  CONSTRAINT `vapt_browsersnapshot_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_browsersnapshot_action_id_fk` FOREIGN KEY (`action_id`) REFERENCES `vapt_actionexecution` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- CONTEXT MANAGEMENT AND PERFORMANCE TRACKING
-- =====================================================

-- Context management operations
DROP TABLE IF EXISTS `vapt_contextoperation`;
CREATE TABLE `vapt_contextoperation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `context_manager_agent_id` bigint NOT NULL,
  `operation_type` varchar(30) NOT NULL,
  `input_size` int DEFAULT NULL,
  `output_size` int DEFAULT NULL,
  `token_reduction` int DEFAULT NULL,
  `processing_duration` decimal(10,3) DEFAULT NULL,
  `llm_metadata` json DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_contextoperation_session_id_idx` (`session_id`),
  KEY `vapt_contextoperation_context_manager_agent_id_idx` (`context_manager_agent_id`),
  KEY `vapt_contextoperation_operation_type_idx` (`operation_type`),
  CONSTRAINT `vapt_contextoperation_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_contextoperation_context_manager_agent_id_fk` FOREIGN KEY (`context_manager_agent_id`) REFERENCES `vapt_agentinstance` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Token usage tracking per session
DROP TABLE IF EXISTS `vapt_tokenusage`;
CREATE TABLE `vapt_tokenusage` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `agent_id` bigint DEFAULT NULL,
  `operation_type` varchar(30) NOT NULL,
  `model_used` varchar(100) NOT NULL,
  `api_provider` varchar(50) NOT NULL,
  `input_tokens` int DEFAULT NULL,
  `output_tokens` int DEFAULT NULL,
  `total_tokens` int NOT NULL,
  `estimated_cost` decimal(10,6) DEFAULT NULL,
  `response_time` decimal(10,3) DEFAULT NULL,
  `timestamp` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_tokenusage_session_id_idx` (`session_id`),
  KEY `vapt_tokenusage_agent_id_idx` (`agent_id`),
  KEY `vapt_tokenusage_operation_type_idx` (`operation_type`),
  KEY `vapt_tokenusage_timestamp_idx` (`timestamp`),
  CONSTRAINT `vapt_tokenusage_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_tokenusage_agent_id_fk` FOREIGN KEY (`agent_id`) REFERENCES `vapt_agentinstance` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Session performance metrics
DROP TABLE IF EXISTS `vapt_performancemetrics`;
CREATE TABLE `vapt_performancemetrics` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `session_id` bigint NOT NULL,
  `metric_name` varchar(100) NOT NULL,
  `metric_value` decimal(15,6) NOT NULL,
  `metric_unit` varchar(20) DEFAULT NULL,
  `measured_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_performancemetrics_session_id_idx` (`session_id`),
  KEY `vapt_performancemetrics_metric_name_idx` (`metric_name`),
  KEY `vapt_performancemetrics_measured_at_idx` (`measured_at`),
  CONSTRAINT `vapt_performancemetrics_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `vapt_orchestrationsession` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- INTEGRATION WITH EXISTING CONTAINER INFRASTRUCTURE  
-- =====================================================

-- Container security posture tracking (links to existing container tables)
DROP TABLE IF EXISTS `vapt_containersecurity`;
CREATE TABLE `vapt_containersecurity` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `container_id` bigint NOT NULL,  -- FK to container_container
  `user_id` int NOT NULL,  -- FK to auth_user (inherited from container)
  `topic_id` bigint DEFAULT NULL,  -- FK to auth_api_app_usertopicmapping (inherited from container)
  `last_vapt_session_id` bigint DEFAULT NULL,  -- FK to latest VAPT session
  `total_vapt_sessions` int DEFAULT 0,
  `total_findings` int DEFAULT 0,
  `critical_findings` int DEFAULT 0,
  `high_findings` int DEFAULT 0,
  `medium_findings` int DEFAULT 0,
  `low_findings` int DEFAULT 0,
  `info_findings` int DEFAULT 0,
  `last_tested_at` datetime(6) DEFAULT NULL,
  `security_score` decimal(5,2) DEFAULT NULL,  -- Calculated security score 0-100
  `security_posture` varchar(20) DEFAULT 'unknown',  -- poor, fair, good, excellent
  `next_recommended_test` datetime(6) DEFAULT NULL,
  `compliance_status` varchar(20) DEFAULT 'unknown',
  `notes` text DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `vapt_containersecurity_container_id_uniq` (`container_id`),
  KEY `vapt_containersecurity_user_id_idx` (`user_id`),
  KEY `vapt_containersecurity_topic_id_idx` (`topic_id`),
  KEY `vapt_containersecurity_last_vapt_session_id_idx` (`last_vapt_session_id`),
  KEY `vapt_containersecurity_security_posture_idx` (`security_posture`),
  KEY `vapt_containersecurity_last_tested_at_idx` (`last_tested_at`),
  CONSTRAINT `vapt_containersecurity_container_id_fk` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_containersecurity_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `vapt_containersecurity_topic_id_fk` FOREIGN KEY (`topic_id`) REFERENCES `auth_api_app_usertopicmapping` (`id`),
  CONSTRAINT `vapt_containersecurity_last_vapt_session_id_fk` FOREIGN KEY (`last_vapt_session_id`) REFERENCES `vapt_orchestrationsession` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Link VAPT findings to container infrastructure components
DROP TABLE IF EXISTS `vapt_containerfindings`;
CREATE TABLE `vapt_containerfindings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `finding_id` bigint NOT NULL,
  `container_id` bigint NOT NULL,
  `docker_image_id` bigint DEFAULT NULL,  -- FK to container_dockerimage
  `container_specs_id` bigint DEFAULT NULL,  -- FK to container_containerspecs  
  `container_env_id` bigint DEFAULT NULL,  -- FK to container_containerenv
  `port_mapping_id` bigint DEFAULT NULL,  -- FK to container_portmappingcontainer
  `network_id` bigint DEFAULT NULL,  -- FK to network_networks
  `affected_component` varchar(50) NOT NULL,  -- env, ports, network, config, application
  `component_details` text DEFAULT NULL,
  `risk_level` varchar(10) NOT NULL,
  `remediation_priority` varchar(10) DEFAULT 'medium',
  `affects_other_containers` tinyint(1) DEFAULT 0,
  `deployment_impact` varchar(20) DEFAULT 'low',  -- low, medium, high, critical
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `vapt_containerfindings_finding_id_idx` (`finding_id`),
  KEY `vapt_containerfindings_container_id_idx` (`container_id`),
  KEY `vapt_containerfindings_docker_image_id_idx` (`docker_image_id`),
  KEY `vapt_containerfindings_container_specs_id_idx` (`container_specs_id`),
  KEY `vapt_containerfindings_container_env_id_idx` (`container_env_id`),
  KEY `vapt_containerfindings_port_mapping_id_idx` (`port_mapping_id`),
  KEY `vapt_containerfindings_network_id_idx` (`network_id`),
  KEY `vapt_containerfindings_affected_component_idx` (`affected_component`),
  KEY `vapt_containerfindings_risk_level_idx` (`risk_level`),
  CONSTRAINT `vapt_containerfindings_finding_id_fk` FOREIGN KEY (`finding_id`) REFERENCES `vapt_securityfinding` (`id`) ON DELETE CASCADE,
  CONSTRAINT `vapt_containerfindings_container_id_fk` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`),
  CONSTRAINT `vapt_containerfindings_docker_image_id_fk` FOREIGN KEY (`docker_image_id`) REFERENCES `container_dockerimage` (`id`),
  CONSTRAINT `vapt_containerfindings_container_specs_id_fk` FOREIGN KEY (`container_specs_id`) REFERENCES `container_containerspecs` (`id`),
  CONSTRAINT `vapt_containerfindings_container_env_id_fk` FOREIGN KEY (`container_env_id`) REFERENCES `container_containerenv` (`id`),
  CONSTRAINT `vapt_containerfindings_port_mapping_id_fk` FOREIGN KEY (`port_mapping_id`) REFERENCES `container_portmappingcontainer` (`id`),
  CONSTRAINT `vapt_containerfindings_network_id_fk` FOREIGN KEY (`network_id`) REFERENCES `network_networks` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =====================================================
-- TRIGGERS FOR AUTOMATIC UPDATES
-- =====================================================

-- Update orchestration session statistics when findings are added
DELIMITER ;;
CREATE TRIGGER `update_session_stats_on_finding_insert` 
AFTER INSERT ON `vapt_securityfinding` 
FOR EACH ROW 
BEGIN
  UPDATE vapt_orchestrationsession 
  SET total_findings = total_findings + 1,
      updated_at = NOW()
  WHERE id = NEW.session_id;
  
  -- Update container security tracking
  IF NEW.container_id IS NOT NULL THEN
    INSERT INTO vapt_containersecurity (
      container_id, user_id, total_findings, last_tested_at, 
      created_at, updated_at, is_active
    ) VALUES (
      NEW.container_id, 
      (SELECT user_id FROM container_container WHERE id = NEW.container_id),
      1, NOW(), NOW(), NOW(), 1
    )
    ON DUPLICATE KEY UPDATE
      total_findings = total_findings + 1,
      last_tested_at = NOW(),
      updated_at = NOW(),
      critical_findings = critical_findings + CASE WHEN NEW.severity = 'critical' THEN 1 ELSE 0 END,
      high_findings = high_findings + CASE WHEN NEW.severity = 'high' THEN 1 ELSE 0 END,
      medium_findings = medium_findings + CASE WHEN NEW.severity = 'medium' THEN 1 ELSE 0 END,
      low_findings = low_findings + CASE WHEN NEW.severity = 'low' THEN 1 ELSE 0 END,
      info_findings = info_findings + CASE WHEN NEW.severity = 'info' THEN 1 ELSE 0 END;
  END IF;
END;;

-- Update session stats when actions are completed
CREATE TRIGGER `update_session_stats_on_action_insert` 
AFTER INSERT ON `vapt_actionexecution` 
FOR EACH ROW 
BEGIN
  UPDATE vapt_orchestrationsession 
  SET total_actions_performed = total_actions_performed + 1,
      updated_at = NOW()
  WHERE id = (SELECT s.id FROM vapt_securityplan p 
              JOIN vapt_urldiscovery u ON p.url_id = u.id 
              JOIN vapt_orchestrationsession s ON u.session_id = s.id 
              WHERE p.id = NEW.plan_id);
  
  UPDATE vapt_securityplan
  SET total_actions_performed = total_actions_performed + 1,
      updated_at = NOW()
  WHERE id = NEW.plan_id;
END;;

-- Update token usage on session
CREATE TRIGGER `update_session_token_usage` 
AFTER INSERT ON `vapt_tokenusage` 
FOR EACH ROW 
BEGIN
  UPDATE vapt_orchestrationsession 
  SET total_tokens_used = total_tokens_used + NEW.total_tokens,
      updated_at = NOW()
  WHERE id = NEW.session_id;
END;;

DELIMITER ;

-- =====================================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- =====================================================

-- Additional composite indexes for common queries
CREATE INDEX `vapt_urldiscovery_session_status_discovery_idx` ON `vapt_urldiscovery` (`session_id`, `status`, `discovery_source`);
CREATE INDEX `vapt_securityplan_status_execution_idx` ON `vapt_securityplan` (`status`, `execution_started_at`);
CREATE INDEX `vapt_actionexecution_plan_iteration_executed_idx` ON `vapt_actionexecution` (`plan_id`, `iteration_number`, `executed_at`);
CREATE INDEX `vapt_securityfinding_session_severity_status_idx` ON `vapt_securityfinding` (`session_id`, `severity`, `status`);
CREATE INDEX `vapt_networkrequest_session_timestamp_idx` ON `vapt_networkrequest` (`session_id`, `request_timestamp`);
CREATE INDEX `vapt_containersecurity_posture_tested_idx` ON `vapt_containersecurity` (`security_posture`, `last_tested_at`);

-- =====================================================
-- ANALYTICS VIEWS FOR REPORTING
-- =====================================================

-- Session overview with complete statistics
CREATE VIEW `v_vapt_session_overview` AS
SELECT 
  s.id as session_id,
  s.session_name,
  s.base_url,
  s.target_hostname,
  u.username,
  s.status,
  s.started_at,
  s.completed_at,
  TIMESTAMPDIFF(MINUTE, s.started_at, COALESCE(s.completed_at, NOW())) as duration_minutes,
  s.total_urls_discovered,
  s.total_urls_tested,
  s.total_plans_executed,
  s.total_actions_performed,
  s.total_findings,
  s.total_tokens_used,
  COUNT(DISTINCT f.id) as critical_findings,
  COUNT(DISTINCT f2.id) as high_findings,
  c.name as container_name,
  c.url as container_url,
  c.running as container_running,
  t.topic as topic_name
FROM vapt_orchestrationsession s
LEFT JOIN auth_user u ON s.user_id = u.id
LEFT JOIN vapt_securityfinding f ON s.id = f.session_id AND f.severity = 'critical'
LEFT JOIN vapt_securityfinding f2 ON s.id = f2.session_id AND f2.severity = 'high'
LEFT JOIN container_container c ON s.container_id = c.id
LEFT JOIN auth_api_app_usertopicmapping t ON s.topic_id = t.id
GROUP BY s.id;

-- Container security posture with full details
CREATE VIEW `v_container_security_dashboard` AS
SELECT 
  c.id as container_id,
  c.name as container_name,
  c.url as container_url,
  c.ip_address,
  c.running,
  u.username as owner,
  t.topic,
  cs.total_vapt_sessions,
  cs.total_findings,
  cs.critical_findings,
  cs.high_findings,
  cs.medium_findings,
  cs.low_findings,
  cs.info_findings,
  cs.last_tested_at,
  cs.security_score,
  cs.security_posture,
  cs.next_recommended_test,
  COUNT(DISTINCT s.id) as active_sessions,
  MAX(s.completed_at) as last_completed_session,
  spec.ram,
  spec.vcpu,
  spec.disk_space,
  di.name as docker_image_name,
  di.version as docker_image_version
FROM container_container c
LEFT JOIN auth_user u ON c.user_id = u.id
LEFT JOIN auth_api_app_usertopicmapping t ON c.topic_id = t.id
LEFT JOIN vapt_containersecurity cs ON c.id = cs.container_id
LEFT JOIN vapt_orchestrationsession s ON c.id = s.container_id AND s.status IN ('running', 'initializing')
LEFT JOIN container_containerspecs spec ON c.id = spec.container_id AND spec.is_active = 1
LEFT JOIN container_containerdockermapping cdm ON c.id = cdm.container_id AND cdm.is_active = 1
LEFT JOIN container_dockerimage di ON cdm.docker_id = di.id AND di.is_active = 1
WHERE c.is_active = 1
GROUP BY c.id;

-- Findings analysis by type and severity
CREATE VIEW `v_vapt_findings_analysis` AS
SELECT 
  s.id as session_id,
  s.session_name,
  c.name as container_name,
  f.finding_type,
  f.severity,
  COUNT(*) as finding_count,
  COUNT(CASE WHEN f.verified = 1 THEN 1 END) as verified_count,
  COUNT(CASE WHEN f.false_positive = 1 THEN 1 END) as false_positive_count,
  COUNT(CASE WHEN f.status = 'new' THEN 1 END) as new_count,
  COUNT(CASE WHEN f.status = 'fixed' THEN 1 END) as fixed_count,
  AVG(f.cvss_score) as avg_cvss_score
FROM vapt_orchestrationsession s
LEFT JOIN vapt_securityfinding f ON s.id = f.session_id
LEFT JOIN container_container c ON s.container_id = c.id
WHERE f.id IS NOT NULL AND f.is_active = 1
GROUP BY s.id, f.finding_type, f.severity;

-- User VAPT activity summary
CREATE VIEW `v_user_vapt_activity` AS
SELECT 
  u.id as user_id,
  u.username,
  u.email,
  COUNT(DISTINCT s.id) as total_sessions,
  COUNT(DISTINCT s.container_id) as containers_tested,
  COUNT(DISTINCT t.id) as topics_with_vapt,
  SUM(s.total_findings) as total_findings,
  SUM(s.total_actions_performed) as total_actions,
  SUM(s.total_tokens_used) as total_tokens,
  MAX(s.started_at) as last_vapt_session,
  AVG(TIMESTAMPDIFF(MINUTE, s.started_at, s.completed_at)) as avg_session_duration,
  COUNT(CASE WHEN s.status = 'completed' THEN 1 END) as completed_sessions,
  COUNT(CASE WHEN s.status = 'failed' THEN 1 END) as failed_sessions
FROM auth_user u
LEFT JOIN vapt_orchestrationsession s ON u.id = s.user_id
LEFT JOIN auth_api_app_usertopicmapping t ON s.topic_id = t.id
WHERE u.is_active = 1
GROUP BY u.id; 