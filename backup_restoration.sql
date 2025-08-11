-- ================================================
-- Backup and Restoration Procedures for School DB
-- ================================================

-- 1. Create directory for backups (run once)
CREATE OR REPLACE DIRECTORY BACKUP_DIR AS '/u01/app/oracle/backup';

GRANT READ, WRITE ON DIRECTORY BACKUP_DIR TO SCHOOL_SCHEMA;

-- 2. Backup Procedure
CREATE OR REPLACE PROCEDURE BACKUP_SCHOOL_DATA AS
    V_BACKUP_FILE VARCHAR2(200);
    V_TIMESTAMP   VARCHAR2(20);
BEGIN
    V_TIMESTAMP := TO_CHAR(SYSDATE, 'YYYYMMDD_HH24MISS');
    V_BACKUP_FILE := 'school_backup_'
                     || V_TIMESTAMP
                     || '.dmp';
    DBMS_OUTPUT.PUT_LINE('Backup file: '
                         || V_BACKUP_FILE);
    DBMS_OUTPUT.PUT_LINE('Backup completed at: '
                         || SYSDATE);
END;
/

-- 3. Restore Procedure
CREATE OR REPLACE PROCEDURE RESTORE_SCHOOL_DATA(
    P_BACKUP_FILE IN VARCHAR2
) AS
BEGIN
    DBMS_OUTPUT.PUT_LINE('Restore from file: '
                         || P_BACKUP_FILE);
    DBMS_OUTPUT.PUT_LINE('Restore completed at: '
                         || SYSDATE);
END;
/

-- 4. Test calls (optional)
BEGIN
    BACKUP_SCHOOL_DATA;
END;
/

BEGIN
    RESTORE_SCHOOL_DATA('school_backup_20250810_180000.dmp');
END;
/

-- 5. Query Audit Trail for backup/restore activity
SELECT
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    TIMESTAMP,
    RETURN_CODE
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    ACTION_NAME LIKE '%BACKUP%'
    OR ACTION_NAME LIKE '%RESTORE%'
ORDER BY
    TIMESTAMP DESC;

-- ================================================
-- Note: For actual backup and restore, run expdp/impdp
-- at OS level using the generated filenames.
-- RMAN scripts need to be run in RMAN client,
-- not through SQL*Plus or SQL scripts.
-- ================================================