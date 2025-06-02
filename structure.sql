-- MySQL dump 10.13  Distrib 8.0.30, for Linux (x86_64)
--
-- Host: localhost    Database: quantumsenses
-- ------------------------------------------------------
-- Server version	8.0.30

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `account_emailaddress`
--

DROP TABLE IF EXISTS `account_emailaddress`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `account_emailaddress` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(254) NOT NULL,
  `verified` tinyint(1) NOT NULL,
  `primary` tinyint(1) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `account_emailaddress_user_id_email_987c8728_uniq` (`user_id`,`email`),
  KEY `account_emailaddress_upper` ((upper(`email`))),
  CONSTRAINT `account_emailaddress_user_id_2c513194_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `account_emailconfirmation`
--

DROP TABLE IF EXISTS `account_emailconfirmation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `account_emailconfirmation` (
  `id` int NOT NULL AUTO_INCREMENT,
  `created` datetime(6) NOT NULL,
  `sent` datetime(6) DEFAULT NULL,
  `key` varchar(64) NOT NULL,
  `email_address_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `key` (`key`),
  KEY `account_emailconfirm_email_address_id_5b7f8c58_fk_account_e` (`email_address_id`),
  CONSTRAINT `account_emailconfirm_email_address_id_5b7f8c58_fk_account_e` FOREIGN KEY (`email_address_id`) REFERENCES `account_emailaddress` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_api_app_user_github_installationid_mapping`
--

DROP TABLE IF EXISTS `auth_api_app_user_github_installationid_mapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_api_app_user_github_installationid_mapping` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `installation_id` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `auth_api_app_user_gi_user_id_0dacb7fa_fk_auth_user` (`user_id`),
  CONSTRAINT `auth_api_app_user_gi_user_id_0dacb7fa_fk_auth_user` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=88 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_api_app_usergithubcreds`
--

DROP TABLE IF EXISTS `auth_api_app_usergithubcreds`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_api_app_usergithubcreds` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `github_username` varchar(100) NOT NULL,
  `github_password` varchar(125) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `auth_api_app_usergithubcreds_user_id_238d6156_fk_auth_user_id` (`user_id`),
  CONSTRAINT `auth_api_app_usergithubcreds_user_id_238d6156_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_api_app_userprofile`
--

DROP TABLE IF EXISTS `auth_api_app_userprofile`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_api_app_userprofile` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `google_id` varchar(100) DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  CONSTRAINT `auth_api_app_userprofile_user_id_f0b71e5e_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=62 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_api_app_usertopicmapping`
--

DROP TABLE IF EXISTS `auth_api_app_usertopicmapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_api_app_usertopicmapping` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `topic` varchar(255) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `user_id` int NOT NULL,
  `is_deployed` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `auth_api_app_usertopicmapping_user_id_47ce1f8a_fk_auth_user_id` (`user_id`),
  CONSTRAINT `auth_api_app_usertopicmapping_user_id_47ce1f8a_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=884 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_group` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_group_permissions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `group_id` int NOT NULL,
  `permission_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_permission` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=145 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_user`
--

DROP TABLE IF EXISTS `auth_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=76 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_user_groups`
--

DROP TABLE IF EXISTS `auth_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user_groups` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `group_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`),
  CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_user_user_permissions`
--

DROP TABLE IF EXISTS `auth_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user_user_permissions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `permission_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `authtoken_token`
--

DROP TABLE IF EXISTS `authtoken_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authtoken_token` (
  `key` varchar(40) NOT NULL,
  `created` datetime(6) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`key`),
  UNIQUE KEY `user_id` (`user_id`),
  CONSTRAINT `authtoken_token_user_id_35299eff_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `backup_backup`
--

DROP TABLE IF EXISTS `backup_backup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `backup_backup` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `file_name` varchar(50) NOT NULL,
  `location` varchar(70) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `backup_backup_container_id_1361acc4_fk_container_container_id` (`container_id`),
  CONSTRAINT `backup_backup_container_id_1361acc4_fk_container_container_id` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `backup_logs`
--

DROP TABLE IF EXISTS `backup_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `backup_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `log_content` varchar(250) NOT NULL,
  `log_type` varchar(50) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `backup_logs_container_id_9118bde9_fk_container_container_id` (`container_id`),
  CONSTRAINT `backup_logs_container_id_9118bde9_fk_container_container_id` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chats_chatmessagesstore`
--

DROP TABLE IF EXISTS `chats_chatmessagesstore`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chats_chatmessagesstore` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `assistant` longtext NOT NULL,
  `user` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `user_topic_mapping_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `chats_chatmessagesst_user_topic_mapping_i_5698599b_fk_auth_api_` (`user_topic_mapping_id`),
  CONSTRAINT `chats_chatmessagesst_user_topic_mapping_i_5698599b_fk_auth_api_` FOREIGN KEY (`user_topic_mapping_id`) REFERENCES `auth_api_app_usertopicmapping` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3646 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_0900_ai_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER `update_usertopicmapping__on_message_insert` AFTER INSERT ON `chats_chatmessagesstore` FOR EACH ROW BEGIN
  UPDATE auth_api_app_usertopicmapping
  SET updated_at = NOW()
  WHERE id = NEW.user_topic_mapping_id;
END */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Table structure for table `container_container`
--

DROP TABLE IF EXISTS `container_container`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_container` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `url` varchar(200) NOT NULL,
  `ip_address` varchar(50) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `user_id` int NOT NULL,
  `running` tinyint(1) NOT NULL,
  `topic_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `container_container_user_id_fe9fab43_fk_auth_user_id` (`user_id`),
  KEY `container_container_topic_id_3d42df74_fk_auth_api_` (`topic_id`),
  CONSTRAINT `container_container_topic_id_3d42df74_fk_auth_api_` FOREIGN KEY (`topic_id`) REFERENCES `auth_api_app_usertopicmapping` (`id`),
  CONSTRAINT `container_container_user_id_fe9fab43_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=461 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_containercredentials`
--

DROP TABLE IF EXISTS `container_containercredentials`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_containercredentials` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `credentials_data` json NOT NULL,
  `database_type` varchar(50) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `container_id` (`container_id`),
  CONSTRAINT `container_containerc_container_id_890738ae_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_containerdockermapping`
--

DROP TABLE IF EXISTS `container_containerdockermapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_containerdockermapping` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `container_id` bigint NOT NULL,
  `docker_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_containerd_docker_id_7ab4f88d_fk_container` (`docker_id`),
  KEY `container_containerd_container_id_b9d608e8_fk_container` (`container_id`),
  CONSTRAINT `container_containerd_container_id_b9d608e8_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`) ON DELETE CASCADE,
  CONSTRAINT `container_containerd_docker_id_7ab4f88d_fk_container` FOREIGN KEY (`docker_id`) REFERENCES `container_dockerimage` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=545 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_containerenv`
--

DROP TABLE IF EXISTS `container_containerenv`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_containerenv` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_containere_container_id_a52f9377_fk_container` (`container_id`),
  CONSTRAINT `container_containere_container_id_a52f9377_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=74 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_containergitlink`
--

DROP TABLE IF EXISTS `container_containergitlink`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_containergitlink` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `gitlink` varchar(200) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_containerg_container_id_e83e619c_fk_container` (`container_id`),
  CONSTRAINT `container_containerg_container_id_e83e619c_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_containerspecs`
--

DROP TABLE IF EXISTS `container_containerspecs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_containerspecs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `ram` int NOT NULL,
  `disk_type` varchar(50) NOT NULL,
  `disk_space` int NOT NULL,
  `ram_type` varchar(50) NOT NULL,
  `vcpu` int NOT NULL,
  `vcpu_type` varchar(50) NOT NULL,
  `autoscalingmode` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_containers_container_id_6b129dd4_fk_container` (`container_id`),
  CONSTRAINT `container_containers_container_id_6b129dd4_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=306 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_containervolumemapping`
--

DROP TABLE IF EXISTS `container_containervolumemapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_containervolumemapping` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `imagevolumelocation` varchar(200) NOT NULL,
  `hostvolumelocation` varchar(200) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_containerv_container_id_b3ac1ea6_fk_container` (`container_id`),
  CONSTRAINT `container_containerv_container_id_b3ac1ea6_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_dockerimage`
--

DROP TABLE IF EXISTS `container_dockerimage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_dockerimage` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` longtext NOT NULL,
  `version` varchar(20) NOT NULL,
  `image_type` varchar(10) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_dockernetwork`
--

DROP TABLE IF EXISTS `container_dockernetwork`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_dockernetwork` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `container_id` bigint NOT NULL,
  `network_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_dockernetw_container_id_3f0403be_fk_container` (`container_id`),
  KEY `container_dockernetw_network_id_2c16f9b5_fk_network_n` (`network_id`),
  CONSTRAINT `container_dockernetw_container_id_3f0403be_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`),
  CONSTRAINT `container_dockernetw_network_id_2c16f9b5_fk_network_n` FOREIGN KEY (`network_id`) REFERENCES `network_networks` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_dockernetworkdmz`
--

DROP TABLE IF EXISTS `container_dockernetworkdmz`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_dockernetworkdmz` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `source_port` int NOT NULL,
  `dest_port` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `docker_network_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_dockernetw_docker_network_id_db7d8d85_fk_container` (`docker_network_id`),
  CONSTRAINT `container_dockernetw_docker_network_id_db7d8d85_fk_container` FOREIGN KEY (`docker_network_id`) REFERENCES `container_dockernetwork` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_portmapping`
--

DROP TABLE IF EXISTS `container_portmapping`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_portmapping` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `port_no` int NOT NULL,
  `port_type` varchar(100) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `docker_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_portmappin_docker_id_ad9a22bc_fk_container` (`docker_id`),
  CONSTRAINT `container_portmappin_docker_id_ad9a22bc_fk_container` FOREIGN KEY (`docker_id`) REFERENCES `container_dockerimage` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `container_portmappingcontainer`
--

DROP TABLE IF EXISTS `container_portmappingcontainer`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `container_portmappingcontainer` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `port_no` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `container_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `container_portmappin_container_id_d45411f9_fk_container` (`container_id`),
  CONSTRAINT `container_portmappin_container_id_d45411f9_fk_container` FOREIGN KEY (`container_id`) REFERENCES `container_container` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_admin_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint unsigned NOT NULL,
  `change_message` longtext NOT NULL,
  `content_type_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `django_admin_log_chk_1` CHECK ((`action_flag` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_content_type` (
  `id` int NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_migrations` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=122 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `network_nattingtable`
--

DROP TABLE IF EXISTS `network_nattingtable`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `network_nattingtable` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `rule_type` varchar(50) NOT NULL,
  `source_port` int NOT NULL,
  `dest_port` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `network_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `network_nattingtable_network_id_c911571d_fk_network_networks_id` (`network_id`),
  CONSTRAINT `network_nattingtable_network_id_c911571d_fk_network_networks_id` FOREIGN KEY (`network_id`) REFERENCES `network_networks` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `network_networks`
--

DROP TABLE IF EXISTS `network_networks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `network_networks` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(70) NOT NULL,
  `public_ip` varchar(50) NOT NULL,
  `internal_ip` varchar(50) NOT NULL,
  `network_type` varchar(50) NOT NULL,
  `network_speed` double NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `socialaccount_socialaccount`
--

DROP TABLE IF EXISTS `socialaccount_socialaccount`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `socialaccount_socialaccount` (
  `id` int NOT NULL AUTO_INCREMENT,
  `provider` varchar(200) NOT NULL,
  `uid` varchar(191) NOT NULL,
  `last_login` datetime(6) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  `extra_data` json NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `socialaccount_socialaccount_provider_uid_fc810c6e_uniq` (`provider`,`uid`),
  KEY `socialaccount_socialaccount_user_id_8146e70c_fk_auth_user_id` (`user_id`),
  CONSTRAINT `socialaccount_socialaccount_user_id_8146e70c_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `socialaccount_socialapp`
--

DROP TABLE IF EXISTS `socialaccount_socialapp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `socialaccount_socialapp` (
  `id` int NOT NULL AUTO_INCREMENT,
  `provider` varchar(30) NOT NULL,
  `name` varchar(40) NOT NULL,
  `client_id` varchar(191) NOT NULL,
  `secret` varchar(191) NOT NULL,
  `key` varchar(191) NOT NULL,
  `provider_id` varchar(200) NOT NULL,
  `settings` json NOT NULL DEFAULT (_utf8mb3'{}'),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `socialaccount_socialtoken`
--

DROP TABLE IF EXISTS `socialaccount_socialtoken`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `socialaccount_socialtoken` (
  `id` int NOT NULL AUTO_INCREMENT,
  `token` longtext NOT NULL,
  `token_secret` longtext NOT NULL,
  `expires_at` datetime(6) DEFAULT NULL,
  `account_id` int NOT NULL,
  `app_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `socialaccount_socialtoken_app_id_account_id_fca4e0ac_uniq` (`app_id`,`account_id`),
  KEY `socialaccount_social_account_id_951f210e_fk_socialacc` (`account_id`),
  CONSTRAINT `socialaccount_social_account_id_951f210e_fk_socialacc` FOREIGN KEY (`account_id`) REFERENCES `socialaccount_socialaccount` (`id`),
  CONSTRAINT `socialaccount_social_app_id_636a42d7_fk_socialacc` FOREIGN KEY (`app_id`) REFERENCES `socialaccount_socialapp` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `waitlist_waitlistdata`
--

DROP TABLE IF EXISTS `waitlist_waitlistdata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `waitlist_waitlistdata` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(254) NOT NULL,
  `company_name` varchar(150) NOT NULL,
  `company_email` varchar(254) NOT NULL,
  `devops_team` tinyint(1) NOT NULL,
  `current_deployment_satisfaction` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-06-02 22:39:09
