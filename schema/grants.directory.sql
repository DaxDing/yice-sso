-- Read-only access to the active-member directory, needed only when a provider declares "directory": true.
-- Run after grants.sql. Replace yice_information with your directory database (SSO_DIRECTORY_DB) if it differs;
-- no directory yet: create one from directory.example.sql. Column lists match exactly what the service reads.

GRANT SELECT (open_id, name, avatar, enabled, dept_id) ON yice_information.member TO 'yice_sso_app'@'%';
GRANT SELECT (dept_id, name) ON yice_information.dept TO 'yice_sso_app'@'%';
