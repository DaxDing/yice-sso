-- Minimal active-member directory for "directory": true providers, when you do not already have one.
-- yice-sso only reads it: keep it filled from your own source (for example a daily sync of the Feishu
-- contact list). A person may sign in while their row exists with enabled = 1; disabling the row signs
-- them out of every app at the next hourly re-check (or at once for fresh=true checks).
-- Rename the database to match SSO_DIRECTORY_DB and grants.directory.sql.

CREATE DATABASE IF NOT EXISTS yice_information DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS yice_information.dept (
  dept_id  VARCHAR(64)  NOT NULL PRIMARY KEY,
  name     VARCHAR(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='部门';

CREATE TABLE IF NOT EXISTS yice_information.member (
  open_id  VARCHAR(64)  NOT NULL PRIMARY KEY COMMENT '主企业登录应用下的飞书 open_id',
  name     VARCHAR(128) NOT NULL,
  avatar   VARCHAR(512) NULL,
  dept_id  VARCHAR(64)  NULL,
  enabled  TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '1 在职可登录；0 停用',
  KEY idx_member_dept (dept_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='在职名单';
