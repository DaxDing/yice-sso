-- yice_sso: authentication facts for the shared login (sessions, OAuth state, login audit).
-- Authorization stays in each web app. Applied once by the RDS maintenance account; the
-- runtime account yice_sso_app never runs DDL (grants: schema/grants.sql).
-- Version 1. self-check compares the live tables and schema_migration against this file.

CREATE DATABASE IF NOT EXISTS yice_sso DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE yice_sso;

CREATE TABLE schema_migration (
  version     INT          NOT NULL PRIMARY KEY,
  name        VARCHAR(128) NOT NULL,
  applied_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) COMMENT='迁移台账';

CREATE TABLE session (
  token_hash   CHAR(64)     NOT NULL PRIMARY KEY COMMENT 'cookie 原值的 SHA-256，原值不落库',
  subject_id   VARCHAR(64)  NOT NULL COMMENT '默认企业为 member.open_id；其他企业为 fs:+sha256[:60]，与 Info 规则一致',
  open_id      VARCHAR(64)  NOT NULL COMMENT '该企业应用下的飞书 open_id；默认企业与 subject_id 相同',
  provider_id  VARCHAR(48)  NOT NULL COMMENT 'providers.v1.json 的 id',
  provider_digest CHAR(64)  NOT NULL COMMENT '登录时企业配置的摘要；配置变化后旧会话一律失效',
  caller_id    VARCHAR(48)  NOT NULL COMMENT '发起登录的应用，callers.v1.json 的 id',
  name         VARCHAR(128) NOT NULL,
  avatar       VARCHAR(512) NULL,
  dept         VARCHAR(128) NULL,
  created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  checked_at   DATETIME(3)  NOT NULL COMMENT '最近一次在职/企业复核',
  expires_at   DATETIME(3)  NOT NULL COMMENT '滑动 30 天',
  KEY idx_session_subject (subject_id),
  KEY idx_session_expires (expires_at)
) COMMENT='登录会话';

CREATE TABLE oauth_state (
  state_hash       CHAR(64)      NOT NULL PRIMARY KEY,
  provider_id      VARCHAR(48)   NOT NULL,
  caller_id        VARCHAR(48)   NOT NULL,
  next_url         VARCHAR(1024) NOT NULL COMMENT '已按 caller origins 校验',
  provider_digest  CHAR(64)      NOT NULL COMMENT '发起时企业配置的摘要，回调时不一致即拒绝',
  created_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires_at       DATETIME(3)   NOT NULL COMMENT '10 分钟，单次消费',
  KEY idx_state_expires (expires_at)
) COMMENT='OAuth state，跨进程单次消费';

CREATE TABLE login_event (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  request_id   CHAR(32)     NOT NULL,
  occurred_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  event_type   VARCHAR(32)  NOT NULL COMMENT 'login / logout / session_revoked；结果看 outcome',
  outcome      VARCHAR(16)  NOT NULL COMMENT 'accepted / denied / error',
  error_code   VARCHAR(64)  NULL,
  subject_id   VARCHAR(64)  NULL COMMENT '换 token 前就失败时为空',
  name         VARCHAR(128) NULL,
  provider_id  VARCHAR(48)  NULL,
  caller_id    VARCHAR(48)  NULL,
  client_ip    VARCHAR(45)  NULL,
  user_agent   VARCHAR(255) NULL,
  UNIQUE KEY uk_event_request (request_id),
  KEY idx_event_time (occurred_at),
  KEY idx_event_subject (subject_id, occurred_at),
  CONSTRAINT chk_event_type CHECK (event_type IN ('login','logout','session_revoked')),
  CONSTRAINT chk_event_outcome CHECK (outcome IN ('accepted','denied','error'))
) COMMENT='登录类审计，只追加';

CREATE TRIGGER login_event_no_update BEFORE UPDATE ON login_event FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'login_event is append-only';
CREATE TRIGGER login_event_no_delete BEFORE DELETE ON login_event FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'login_event is append-only';

INSERT INTO schema_migration (version, name) VALUES (1, 'init');
