-- Grants for the runtime account; declaration: aliyun-subaccount/grants/yice_sso_app.json.
-- Run by the RDS maintenance account after the account exists (created in the RDS console;
-- the password never appears in a file). Column lists match exactly what the service reads.

GRANT SELECT, INSERT, UPDATE, DELETE ON yice_sso.session TO 'yice_sso_app'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON yice_sso.oauth_state TO 'yice_sso_app'@'%';
GRANT SELECT, INSERT ON yice_sso.login_event TO 'yice_sso_app'@'%';
GRANT SELECT ON yice_sso.schema_migration TO 'yice_sso_app'@'%';
