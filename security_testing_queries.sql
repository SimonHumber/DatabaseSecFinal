-- =====================================================
-- Security Testing Queries for School Database in Oracle 19c
-- =====================================================
-- This script contains queries to test the security implementation
-- and simulate various attack scenarios in a school environment
-- =====================================================

-- =====================================================
-- 1. SQL INJECTION TESTING SCENARIOS
-- =====================================================

-- Test 1: Basic SQL Injection attempt on student search
-- This should be prevented by proper parameter binding
-- Simulated malicious input: ' OR '1'='1
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME,
    EMAIL
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    FIRST_NAME = 'Alex'
    OR '1'='1';

-- Test 2: Union-based SQL injection attempt
-- Simulated malicious input: ' UNION SELECT username, password, null, null FROM dba_users --
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME,
    EMAIL
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    FIRST_NAME = 'Alex'
UNION
SELECT
    USERNAME,
    PASSWORD,
    NULL,
    NULL
FROM
    DBA_USERS;

-- Test 3: Comment-based SQL injection
-- Simulated malicious input: '; DROP TABLE students; --
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    FIRST_NAME = 'Alex';

DROP TABLE SCHOOL_SCHEMA.STUDENTS;

-- Test 4: Blind SQL injection attempt
-- Simulated malicious input: ' AND (SELECT COUNT(*) FROM dba_users) > 0 --
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    FIRST_NAME = 'Alex'
    AND (
        SELECT
            COUNT(*)
        FROM
            DBA_USERS
    ) > 0;

-- Test 5: Grade manipulation attempt
-- Simulated malicious input: '; UPDATE enrollments SET grade = 'A+' WHERE student_id = 2001; --
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    FIRST_NAME = 'Alex';

UPDATE SCHOOL_SCHEMA.ENROLLMENTS
SET
    GRADE = 'A+'
WHERE
    STUDENT_ID = 2001;

-- =====================================================
-- 2. PRIVILEGE ESCALATION TESTING
-- =====================================================

-- Test 1: Attempt to access DBA views without privileges
SELECT
    USERNAME,
    ACCOUNT_STATUS
FROM
    DBA_USERS;

-- Test 2: Attempt to grant system privileges
GRANT DBA TO TEACHER_USER;

-- Test 3: Attempt to create user without proper privileges
CREATE USER TEST_USER IDENTIFIED BY password;

-- Test 4: Attempt to alter system parameters
ALTER SYSTEM SET PROCESSES = 200;

-- Test 5: Attempt to access audit trail without audit role
SELECT
    USERNAME,
    ACTION_NAME,
    TIMESTAMP
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    USERNAME = 'TEACHER_USER';

-- Test 6: Attempt to access sensitive student data without authorization
SELECT
    STUDENT_ID,
    SIN,
    ADDRESS,
    PARENT_PHONE
FROM
    SCHOOL_SCHEMA.STUDENTS;

-- =====================================================
-- 3. DATA ACCESS CONTROL TESTING
-- =====================================================

-- Test 1: Attempt to access GPA information without proper role
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME,
    GPA
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    STUDENT_ID = 2001;

-- Test 2: Attempt to access sensitive student data (SIN, Address, Parent Phone)
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME,
    SIN,
    ADDRESS,
    PARENT_PHONE
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    STUDENT_ID = 2001;

-- Test 3: Attempt to access teacher salary information without proper role
SELECT
    TEACHER_ID,
    FIRST_NAME,
    LAST_NAME,
    SALARY
FROM
    SCHOOL_SCHEMA.TEACHERS
WHERE
    TEACHER_ID = 1001;

-- Test 4: Attempt to access course information without authorization
SELECT
    COURSE_ID,
    COURSE_NAME,
    CREDITS,
    MAX_STUDENTS
FROM
    SCHOOL_SCHEMA.COURSES
WHERE
    COURSE_ID = 3001;

-- Test 5: Attempt to modify grades without proper privileges
UPDATE SCHOOL_SCHEMA.ENROLLMENTS
SET
    GRADE = 'A+',
    FINAL_SCORE = 100
WHERE
    STUDENT_ID = 2001;

-- Test 6: Attempt to delete student records without authorization
DELETE FROM SCHOOL_SCHEMA.STUDENTS
WHERE
    STUDENT_ID = 2001;

-- Test 7: Attempt to access department information without authorization
SELECT
    DEPARTMENT_ID,
    DEPARTMENT_NAME,
    LOCATION
FROM
    SCHOOL_SCHEMA.DEPARTMENTS
WHERE
    DEPARTMENT_ID = 4001;

-- =====================================================
-- 4. AUDIT TRAIL VERIFICATION
-- =====================================================

-- Verify that login attempts are being audited
SELECT
    USERNAME,
    ACTION_NAME,
    TIMESTAMP,
    RETURN_CODE
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    ACTION_NAME = 'LOGON'
ORDER BY
    TIMESTAMP DESC;

-- Verify that student data access is being audited
SELECT
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    TIMESTAMP
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    OBJ_NAME IN ('STUDENTS', 'ENROLLMENTS', 'TEACHERS', 'COURSES')
ORDER BY
    TIMESTAMP DESC;

-- Verify that grade changes are being audited
SELECT
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    TIMESTAMP
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    OBJ_NAME = 'ENROLLMENTS'
    AND ACTION_NAME IN ('UPDATE', 'INSERT')
ORDER BY
    TIMESTAMP DESC;

-- Verify that privilege changes are being audited
SELECT
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    TIMESTAMP
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    ACTION_NAME IN ('GRANT', 'REVOKE')
ORDER BY
    TIMESTAMP DESC;

-- Check for failed login attempts
SELECT
    USERNAME,
    TIMESTAMP,
    ACTION_NAME,
    RETURN_CODE
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    ACTION_NAME = 'LOGON'
    AND RETURN_CODE != 0
ORDER BY
    TIMESTAMP DESC;

-- =====================================================
-- 5. DATA REDACTION VERIFICATION
-- =====================================================

-- Test 1: Verify student address redaction (should show partial masking)
-- Note: SIN is encrypted, not redacted
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME,
    ADDRESS
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    STUDENT_ID = 2001;

-- Test 2: Verify address redaction works for different user roles
-- Connect as different users to test the redaction policy
-- ADMIN_USER and COUNSELOR_USER should see full addresses
-- Other users should see redacted addresses

-- Test 3: Verify no redaction on other student fields
-- Parent phone and other fields should be visible (no redaction policy)
SELECT
    STUDENT_ID,
    FIRST_NAME,
    LAST_NAME,
    PARENT_PHONE,
    EMAIL
FROM
    SCHOOL_SCHEMA.STUDENTS
WHERE
    STUDENT_ID = 2001;

-- Test 4: Verify teacher data has no redaction
-- Teachers table has no redaction policies (SIN is encrypted)
SELECT
    TEACHER_ID,
    FIRST_NAME,
    LAST_NAME,
    SALARY,
    PHONE
FROM
    SCHOOL_SCHEMA.TEACHERS
WHERE
    TEACHER_ID = 1001;

-- =====================================================
-- 6. ENCRYPTION VERIFICATION
-- =====================================================

-- Check if tablespaces are encrypted
SELECT
    TABLESPACE_NAME,
    ENCRYPTION
FROM
    DBA_TABLESPACES
WHERE
    TABLESPACE_NAME IN ('SECURE_DATA', 'ENCRYPTED_DATA');

-- Check encryption status of datafiles
SELECT
    FILE_NAME,
    ENCRYPTION_NAME,
    ENCRYPTION_ALGORITHM
FROM
    DBA_DATA_FILES
WHERE
    TABLESPACE_NAME IN ('SECURE_DATA', 'ENCRYPTED_DATA');

-- Check if SIN columns are encrypted
SELECT
    TABLE_NAME,
    COLUMN_NAME,
    ENCRYPTION_ALG
FROM
    USER_ENCRYPTED_COLUMNS
WHERE
    TABLE_NAME IN ('STUDENTS', 'TEACHERS')
    AND COLUMN_NAME = 'SIN';

-- =====================================================
-- 7. SECURE PROCEDURE TESTING
-- =====================================================

-- Test 1: Call secure procedure with proper privileges
DECLARE
    V_GPA NUMBER;
BEGIN
    SCHOOL_SCHEMA.GET_STUDENT_GPA(2001, V_GPA);
    DBMS_OUTPUT.PUT_LINE('GPA: '
                         || V_GPA);
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: '
                             || SQLERRM);
END;
/

-- Test 2: Call secure procedure without proper privileges
-- This should fail for users without ADMIN_USER, TEACHER_USER, or COUNSELOR_USER role
DECLARE
    V_GPA NUMBER;
BEGIN
    SCHOOL_SCHEMA.GET_STUDENT_GPA(2001, V_GPA);
    DBMS_OUTPUT.PUT_LINE('GPA: '
                         || V_GPA);
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: '
                             || SQLERRM);
END;
/

-- Test 3: Test grade update procedure
BEGIN
    SCHOOL_SCHEMA.UPDATE_STUDENT_GRADE(4001, 'A+', 95.0);
    DBMS_OUTPUT.PUT_LINE('Grade updated successfully');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: '
                             || SQLERRM);
END;
/

-- Test 4: Test student enrollment procedure
BEGIN
    SCHOOL_SCHEMA.ENROLL_STUDENT_IN_COURSE(2003, 3003);
    DBMS_OUTPUT.PUT_LINE('Student enrolled successfully');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: '
                             || SQLERRM);
END;
/

-- =====================================================
-- 8. PASSWORD POLICY TESTING
-- =====================================================

-- Check password profile settings
SELECT
    PROFILE,
    RESOURCE_NAME,
    RESOURCE_TYPE,
    LIMIT
FROM
    DBA_PROFILES
WHERE
    PROFILE = 'SECURE_PROFILE'
ORDER BY
    RESOURCE_NAME;

-- Check user account status
SELECT
    USERNAME,
    ACCOUNT_STATUS,
    LOCK_DATE,
    EXPIRY_DATE
FROM
    DBA_USERS
WHERE
    USERNAME IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER', 'REGISTRAR_USER', 'READ_ONLY_USER');

-- =====================================================
-- 9. ROLE AND PRIVILEGE VERIFICATION
-- =====================================================

-- =====================================================
-- 10. SECURITY MONITORING QUERIES
-- =====================================================

-- Check user roles
SELECT
    GRANTEE,
    GRANTED_ROLE,
    ADMIN_OPTION
FROM
    DBA_ROLE_PRIVS
WHERE
    GRANTEE IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER', 'REGISTRAR_USER', 'READ_ONLY_USER');

-- Check system privileges
SELECT
    GRANTEE,
    PRIVILEGE,
    ADMIN_OPTION
FROM
    DBA_SYS_PRIVS
WHERE
    GRANTEE IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER', 'REGISTRAR_USER', 'READ_ONLY_USER');

-- Check object privileges
SELECT
    GRANTEE,
    TABLE_NAME,
    PRIVILEGE,
    GRANTABLE
FROM
    DBA_TAB_PRIVS
WHERE
    GRANTEE IN ('ADMIN_ROLE', 'TEACHER_ROLE', 'COUNSELOR_ROLE', 'REGISTRAR_ROLE', 'READ_ONLY_ROLE');

-- =====================================================
-- 11. SECURITY CONFIGURATION VERIFICATION
-- =====================================================

-- Verify audit policies are enabled
SELECT
    POLICY_NAME,
    ENABLED_OPTION,
    AUDIT_OPTION
FROM
    AUDIT_POLICIES
ORDER BY
    POLICY_NAME;

-- Verify redaction policies are active
SELECT
    OBJECT_SCHEMA,
    OBJECT_NAME,
    COLUMN_NAME,
    POLICY_NAME,
    FUNCTION_TYPE
FROM
    REDACTION_POLICIES
ORDER BY
    OBJECT_NAME,
    COLUMN_NAME;

-- Check database security settings
SELECT
    NAME,
    VALUE
FROM
    V$PARAMETER
WHERE
    NAME IN ('audit_trail', 'audit_file_dest', 'audit_sys_operations');

-- =====================================================
-- 12. PERFORMANCE IMPACT ASSESSMENT
-- =====================================================

-- Check audit trail size
SELECT
    COUNT(*) AS AUDIT_RECORDS_COUNT
FROM
    UNIFIED_AUDIT_TRAIL;

-- Check audit trail growth rate
SELECT
    TRUNC(TIMESTAMP, 'DD') AS AUDIT_DATE,
    COUNT(*)               AS DAILY_AUDIT_COUNT
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    TIMESTAMP > SYSDATE - 30
GROUP BY
    TRUNC(TIMESTAMP, 'DD')
ORDER BY
    AUDIT_DATE;

-- Check tablespace usage
SELECT
    TABLESPACE_NAME,
    BYTES/1024/1024 AS SIZE_MB,
    (BYTES - FREE_SPACE)/1024/1024 AS USED_MB
FROM
    DBA_TABLESPACES T,
    (
        SELECT
            TABLESPACE_NAME,
            SUM(BYTES)      AS FREE_SPACE
        FROM
            DBA_FREE_SPACE
        GROUP BY
            TABLESPACE_NAME
    )               F
WHERE
    T.TABLESPACE_NAME = F.TABLESPACE_NAME(+);

-- =====================================================
-- 13. SECURITY REPORTING QUERIES
-- =====================================================

-- Generate security summary report
SELECT
    'User Accounts'         AS CATEGORY,
    COUNT(*)                AS COUNT
FROM
    DBA_USERS
WHERE
    USERNAME IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER', 'REGISTRAR_USER', 'READ_ONLY_USER')
UNION
ALL
SELECT
    'Audit Policies'        AS CATEGORY,
    COUNT(*)                AS COUNT
FROM
    AUDIT_POLICIES
UNION
ALL
SELECT
    'Redaction Policies'    AS CATEGORY,
    COUNT(*)                AS COUNT
FROM
    REDACTION_POLICIES
UNION
ALL
SELECT
    'Encrypted Tablespaces' AS CATEGORY,
    COUNT(*)                AS COUNT
FROM
    DBA_TABLESPACES
WHERE
    ENCRYPTION = 'ENCRYPTED';

-- Generate user activity report
SELECT
    USERNAME,
    COUNT(*) AS TOTAL_ACTIONS,
    COUNT(CASE WHEN ACTION_NAME = 'LOGON' THEN 1 END) AS LOGINS,
    COUNT(CASE WHEN ACTION_NAME = 'LOGOFF' THEN 1 END) AS LOGOFFS,
    COUNT(CASE WHEN ACTION_NAME IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE') THEN 1 END) AS DATA_OPERATIONS
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    TIMESTAMP > SYSDATE - 7
GROUP BY
    USERNAME
ORDER BY
    TOTAL_ACTIONS DESC;

-- Generate student data access report
SELECT
    USERNAME,
    OBJ_NAME,
    COUNT(*)       AS ACCESS_COUNT,
    MIN(TIMESTAMP) AS FIRST_ACCESS,
    MAX(TIMESTAMP) AS LAST_ACCESS
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    OBJ_NAME IN ('STUDENTS', 'ENROLLMENTS', 'TEACHERS', 'COURSES')
    AND TIMESTAMP > SYSDATE - 7
GROUP BY
    USERNAME,
    OBJ_NAME
ORDER BY
    USERNAME,
    ACCESS_COUNT DESC;

-- Generate grade change audit report
SELECT
    USERNAME,
    COUNT(*)       AS GRADE_CHANGES,
    MIN(TIMESTAMP) AS FIRST_CHANGE,
    MAX(TIMESTAMP) AS LAST_CHANGE
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    OBJ_NAME = 'ENROLLMENTS'
    AND ACTION_NAME = 'UPDATE'
    AND TIMESTAMP > SYSDATE - 30
GROUP BY
    USERNAME
ORDER BY
    GRADE_CHANGES DESC;

-- =====================================================
-- 14. SCHOOL-SPECIFIC SECURITY TESTING
-- =====================================================

-- Test 1: Attempt to access student SIN information
SELECT
    STUDENT_ID,
    SIN
FROM
    SCHOOL_SCHEMA.STUDENTS;

-- Test 2: Attempt to access teacher SIN information
SELECT
    TEACHER_ID,
    SIN
FROM
    SCHOOL_SCHEMA.TEACHERS;

-- Test 3: Attempt to modify course grades without authorization
UPDATE SCHOOL_SCHEMA.ENROLLMENTS
SET
    GRADE = 'A+'
WHERE
    STUDENT_ID = 2001;

-- Test 4: Attempt to access teacher salary information
SELECT
    TEACHER_ID,
    SALARY
FROM
    SCHOOL_SCHEMA.TEACHERS;

-- Test 5: Attempt to access course enrollment information without proper role
SELECT
    *
FROM
    SCHOOL_SCHEMA.ENROLLMENTS
WHERE
    STUDENT_ID = 2001;

-- Test 6: Attempt to access department information without authorization
SELECT
    *
FROM
    SCHOOL_SCHEMA.DEPARTMENTS
WHERE
    DEPARTMENT_ID = 4001;

-- Test 7: Attempt to enroll student in non-existent course
BEGIN
    SCHOOL_SCHEMA.ENROLL_STUDENT_IN_COURSE(2001, 9999);
END;
/

-- Test 8: Attempt to access student data outside of authorized hours
-- This would be tested by running queries during non-school hours

-- =====================================================
-- END OF SECURITY TESTING QUERIES
-- =====================================================

PROMPT =====================================================

PROMPT School Database Security Testing Queries Complete

PROMPT =====================================================

PROMPT

PROMPT Testing scenarios covered:

PROMPT - SQL injection attempts on student data

PROMPT - Privilege escalation tests

PROMPT - Student data access control verification

PROMPT - Grade manipulation attempts

PROMPT - Audit trail verification

PROMPT - Data redaction testing for student information

PROMPT - Encryption verification

PROMPT - Secure procedure testing

PROMPT - Security monitoring queries

PROMPT - Performance impact assessment

PROMPT - School-specific security reporting

PROMPT

PROMPT Run these queries to validate your school security implementation

PROMPT =====================================================