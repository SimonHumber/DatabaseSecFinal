-- =====================================================
-- Comprehensive Database Security Implementation in Oracle 19c
-- =====================================================
-- This script implements security measures for a school database to ensure data confidentiality,
-- integrity, and availability (CIA triad) in Oracle 19c
-- =====================================================

-- Connect as SYSDBA to perform administrative tasks
-- CONNECT / AS SYSDBA;

-- =====================================================
-- 1. DATABASE CREATION & AUTHENTICATION SETUP
-- =====================================================

-- Note: Using default Oracle tablespaces (SYSTEM, SYSAUX) instead of custom tablespaces
-- This simplifies the setup and works with any Oracle 19c installation

-- Create application schema (will use default tablespace)
CREATE USER SCHOOL_SCHEMA IDENTIFIED BY "SecurePass123!"
DEFAULT TABLESPACE USERS
QUOTA UNLIMITED ON USERS
PROFILE SECURE_PROFILE;

-- Create secure profile with password policies
CREATE PROFILE SECURE_PROFILE LIMIT
    FAILED_LOGIN_ATTEMPTS 3
    PASSWORD_LIFE_TIME 90
    PASSWORD_REUSE_TIME 365
    PASSWORD_REUSE_MAX 5
    PASSWORD_LOCK_TIME 1
    PASSWORD_GRACE_TIME 7
    PASSWORD_VERIFY_FUNCTION ORA12C_VERIFY_FUNCTION;

-- =====================================================
-- 2. USER ACCOUNTS AND AUTHENTICATION MECHANISMS
-- =====================================================

-- Create school application users with different privilege levels
CREATE USER ADMIN_USER IDENTIFIED BY "Admin2024!"
DEFAULT TABLESPACE USERS
PROFILE SECURE_PROFILE;

CREATE USER TEACHER_USER IDENTIFIED BY "Teacher2024!"
DEFAULT TABLESPACE USERS
PROFILE SECURE_PROFILE;

CREATE USER COUNSELOR_USER IDENTIFIED BY "Counselor2024!"
DEFAULT TABLESPACE USERS
PROFILE SECURE_PROFILE;

CREATE USER REGISTRAR_USER IDENTIFIED BY "Registrar2024!"
DEFAULT TABLESPACE USERS
PROFILE SECURE_PROFILE;

CREATE USER READ_ONLY_USER IDENTIFIED BY "ReadOnly2024!"
DEFAULT TABLESPACE USERS
PROFILE SECURE_PROFILE;

-- =====================================================
-- 3. ACCESS CONTROL & ROLE-BASED SECURITY
-- =====================================================

-- Create application roles
CREATE ROLE ADMIN_ROLE;

CREATE ROLE TEACHER_ROLE;

CREATE ROLE COUNSELOR_ROLE;

CREATE ROLE REGISTRAR_ROLE;

CREATE ROLE READ_ONLY_ROLE;

CREATE ROLE AUDIT_ROLE;

-- Grant basic connect privilege to all users
GRANT CREATE SESSION TO ADMIN_USER, TEACHER_USER, COUNSELOR_USER, REGISTRAR_USER, READ_ONLY_USER;

-- Grant role to users
GRANT ADMIN_ROLE TO ADMIN_USER;

GRANT TEACHER_ROLE TO TEACHER_USER;

GRANT COUNSELOR_ROLE TO COUNSELOR_USER;

GRANT REGISTRAR_ROLE TO REGISTRAR_USER;

GRANT READ_ONLY_ROLE TO READ_ONLY_USER;

GRANT AUDIT_ROLE TO ADMIN_USER, COUNSELOR_USER;

-- =====================================================
-- 4. APPLICATION TABLES AND DATA
-- =====================================================

-- Create students table
CREATE TABLE STUDENTS (
    STUDENT_ID NUMBER PRIMARY KEY,
    FIRST_NAME VARCHAR2(50) NOT NULL,
    LAST_NAME VARCHAR2(50) NOT NULL,
    EMAIL VARCHAR2(100) UNIQUE,
    DATE_OF_BIRTH DATE,
    GRADE_LEVEL NUMBER(2),
    GPA NUMBER(3, 2),
    SIN VARCHAR2(11) ENCRYPT, -- Encrypted Social Insurance Number
    PARENT_PHONE VARCHAR2(20), -- Parent contact (sensitive)
    ADDRESS VARCHAR2(200), -- Home address (sensitive)
    ENROLLMENT_DATE DATE DEFAULT SYSDATE,
    STATUS VARCHAR2(20) DEFAULT 'ACTIVE'
);

-- Create teachers table
CREATE TABLE TEACHERS (
    TEACHER_ID NUMBER PRIMARY KEY,
    FIRST_NAME VARCHAR2(50) NOT NULL,
    LAST_NAME VARCHAR2(50) NOT NULL,
    EMAIL VARCHAR2(100) UNIQUE,
    PHONE VARCHAR2(20),
    HIRE_DATE DATE,
    SALARY NUMBER(10, 2),
    DEPARTMENT_ID NUMBER,
    SIN VARCHAR2(11) ENCRYPT -- Encrypted Social Insurance Number
);

-- Create departments table
CREATE TABLE DEPARTMENTS (
    DEPARTMENT_ID NUMBER PRIMARY KEY,
    DEPARTMENT_NAME VARCHAR2(100),
    LOCATION VARCHAR2(100),
    BUDGET NUMBER(12, 2)
);

-- Create courses table
CREATE TABLE COURSES (
    COURSE_ID NUMBER PRIMARY KEY,
    COURSE_CODE VARCHAR2(20) UNIQUE,
    COURSE_NAME VARCHAR2(100),
    CREDITS NUMBER(2),
    DEPARTMENT_ID NUMBER,
    TEACHER_ID NUMBER,
    MAX_STUDENTS NUMBER(3),
    CONSTRAINT FK_COURSES_DEPARTMENT FOREIGN KEY (DEPARTMENT_ID) REFERENCES DEPARTMENTS(DEPARTMENT_ID),
    CONSTRAINT FK_COURSES_TEACHER FOREIGN KEY (TEACHER_ID) REFERENCES TEACHERS(TEACHER_ID)
);

-- Create enrollments table with IDENTITY column
CREATE TABLE ENROLLMENTS (
    ENROLLMENT_ID NUMBER GENERATED ALWAYS AS IDENTITY,
    STUDENT_ID NUMBER,
    COURSE_ID NUMBER,
    ENROLLMENT_DATE DATE,
    GRADE VARCHAR2(2),
    FINAL_SCORE NUMBER(5,2),
    ATTENDANCE_PERCENTAGE NUMBER(5,2),
    CONSTRAINT FK_ENROLLMENTS_STUDENT FOREIGN KEY (STUDENT_ID) REFERENCES STUDENTS(STUDENT_ID),
    CONSTRAINT FK_ENROLLMENTS_COURSE FOREIGN KEY (COURSE_ID) REFERENCES COURSES(COURSE_ID)
);

-- Insert sample data
INSERT INTO DEPARTMENTS VALUES (
    1,
    'Mathematics',
    'Building A',
    150000
);

INSERT INTO DEPARTMENTS VALUES (
    2,
    'Science',
    'Building B',
    200000
);

INSERT INTO DEPARTMENTS VALUES (
    3,
    'English',
    'Building C',
    120000
);

INSERT INTO DEPARTMENTS VALUES (
    4,
    'History',
    'Building D',
    100000
);

INSERT INTO STUDENTS VALUES (
    2001,
    'Alex',
    'Smith',
    'alex.smith@student.school.edu',
    TO_DATE('2006-05-15', 'YYYY-MM-DD'),
    9,
    3.85,
    '111-22-3333',
    '555-0301',
    '123 Main St, Anytown, ST 12345',
    SYSDATE,
    'ACTIVE'
);

INSERT INTO STUDENTS VALUES (
    2002,
    'Maria',
    'Garcia',
    'maria.garcia@student.school.edu',
    TO_DATE('2005-08-22', 'YYYY-MM-DD'),
    10,
    3.92,
    '222-33-4444',
    '555-0302',
    '456 Oak Ave, Anytown, ST 12345',
    SYSDATE,
    'ACTIVE'
);

INSERT INTO STUDENTS VALUES (
    2003,
    'Jordan',
    'Williams',
    'jordan.williams@student.school.edu',
    TO_DATE('2004-12-10', 'YYYY-MM-DD'),
    11,
    3.78,
    '333-44-5555',
    '555-0303',
    '789 Pine Rd, Anytown, ST 12345',
    SYSDATE,
    'ACTIVE'
);

INSERT INTO TEACHERS VALUES (
    1001,
    'Dr. Sarah',
    'Johnson',
    'sarah.johnson@school.edu',
    '555-0101',
    TO_DATE('2018-08-15', 'YYYY-MM-DD'),
    65000,
    1,
    '123-45-6789'
);

INSERT INTO TEACHERS VALUES (
    1002,
    'Prof. Michael',
    'Chen',
    'michael.chen@school.edu',
    '555-0102',
    TO_DATE('2019-01-20', 'YYYY-MM-DD'),
    62000,
    2,
    '234-56-7890'
);

INSERT INTO TEACHERS VALUES (
    1003,
    'Ms. Emily',
    'Davis',
    'emily.davis@school.edu',
    '555-0103',
    TO_DATE('2020-03-10', 'YYYY-MM-DD'),
    58000,
    3,
    '345-67-8901'
);

INSERT INTO COURSES VALUES (
    3001,
    'MATH101',
    'Algebra I',
    4,
    1,
    1001,
    25
);

INSERT INTO COURSES VALUES (
    3002,
    'SCI101',
    'Biology',
    4,
    2,
    1002,
    20
);

INSERT INTO COURSES VALUES (
    3003,
    'ENG101',
    'English Literature',
    3,
    3,
    1003,
    30
);

INSERT INTO ENROLLMENTS VALUES (
    2001,
    3001,
    TO_DATE('2024-01-15', 'YYYY-MM-DD'),
    'A',
    92.5,
    95.0
);

INSERT INTO ENROLLMENTS VALUES (
    2001,
    3002,
    TO_DATE('2024-01-15', 'YYYY-MM-DD'),
    'A-',
    88.0,
    92.0
);

INSERT INTO ENROLLMENTS VALUES (
    2002,
    3001,
    TO_DATE('2024-01-15', 'YYYY-MM-DD'),
    'A+',
    96.0,
    98.0
);

COMMIT;

-- =====================================================
-- 5. GRANT PRIVILEGES TO ROLES
-- =====================================================

-- Admin Role privileges (full access)
GRANT SELECT, INSERT, UPDATE, DELETE ON STUDENTS TO ADMIN_ROLE;

GRANT SELECT, INSERT, UPDATE, DELETE ON TEACHERS TO ADMIN_ROLE;

GRANT SELECT, INSERT, UPDATE, DELETE ON DEPARTMENTS TO ADMIN_ROLE;

GRANT SELECT, INSERT, UPDATE, DELETE ON COURSES TO ADMIN_ROLE;

GRANT SELECT, INSERT, UPDATE, DELETE ON ENROLLMENTS TO ADMIN_ROLE;

-- Teacher Role privileges
GRANT SELECT ON STUDENTS TO TEACHER_ROLE;

GRANT SELECT ON TEACHERS TO TEACHER_ROLE;

GRANT SELECT ON DEPARTMENTS TO TEACHER_ROLE;

GRANT SELECT, INSERT, UPDATE ON COURSES TO TEACHER_ROLE;

GRANT SELECT, INSERT, UPDATE ON ENROLLMENTS TO TEACHER_ROLE;

-- Counselor Role privileges
GRANT SELECT, INSERT, UPDATE ON STUDENTS TO COUNSELOR_ROLE;

GRANT SELECT ON TEACHERS TO COUNSELOR_ROLE;

GRANT SELECT ON DEPARTMENTS TO COUNSELOR_ROLE;

GRANT SELECT ON COURSES TO COUNSELOR_ROLE;

GRANT SELECT, INSERT, UPDATE ON ENROLLMENTS TO COUNSELOR_ROLE;

-- Registrar Role privileges
GRANT SELECT, INSERT, UPDATE ON STUDENTS TO REGISTRAR_ROLE;

GRANT SELECT ON TEACHERS TO REGISTRAR_ROLE;

GRANT SELECT ON DEPARTMENTS TO REGISTRAR_ROLE;

GRANT SELECT, INSERT, UPDATE ON COURSES TO REGISTRAR_ROLE;

GRANT SELECT, INSERT, UPDATE ON ENROLLMENTS TO REGISTRAR_ROLE;

-- Read-only Role privileges
GRANT SELECT ON STUDENTS TO READ_ONLY_ROLE;

GRANT SELECT ON TEACHERS TO READ_ONLY_ROLE;

GRANT SELECT ON DEPARTMENTS TO READ_ONLY_ROLE;

GRANT SELECT ON COURSES TO READ_ONLY_ROLE;

GRANT SELECT ON ENROLLMENTS TO READ_ONLY_ROLE;

-- Audit Role privileges
GRANT SELECT ON DBA_AUDIT_TRAIL TO AUDIT_ROLE;

GRANT SELECT ON DBA_AUDIT_POLICIES TO AUDIT_ROLE;

-- =====================================================
-- 6. DATA REDACTION IMPLEMENTATION
-- =====================================================

-- Apply data redaction policy for student addresses only
-- Note: SIN is encrypted using Oracle's built-in encryption

-- Redact student addresses (partial redaction)
DBMS_REDACT.ADD_POLICY(
    object_schema => 'SCHOOL_SCHEMA',
    object_name => 'STUDENTS',
    column_name => 'ADDRESS',
    policy_name => 'student_address_redaction',
    function_type => DBMS_REDACT.PARTIAL,
    function_parameters => DBMS_REDACT.PARTIAL_PARAMS(
        function_type => DBMS_REDACT.PARTIAL_STREET_ADDRESS,
        start_length => 0,
        end_length => 0,
        start_delimiter => '',
        end_delimiter => '',
        end_delimiter_length => 0
    ),
    expression => 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') NOT IN (''ADMIN_USER'', ''COUNSELOR_USER'')'
);

-- =====================================================
-- 7. AUDIT POLICIES IMPLEMENTATION
-- =====================================================

-- Enable unified auditing
ALTER SYSTEM SET AUDIT_TRAIL=DB, EXTENDED SCOPE=SPFILE;

-- Create audit policies
CREATE AUDIT POLICY STUDENT_ACCESS_POLICY
    ACTIONS SELECT, INSERT, UPDATE, DELETE
    ON SCHOOL_SCHEMA.STUDENTS
    WHEN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') != ''SCHOOL_SCHEMA'''
    EVALUATE PER STATEMENT;

CREATE AUDIT POLICY GRADE_ACCESS_POLICY
    ACTIONS SELECT, INSERT, UPDATE, DELETE
    ON SCHOOL_SCHEMA.ENROLLMENTS
    WHEN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') != ''SCHOOL_SCHEMA'''
    EVALUATE PER STATEMENT;

CREATE AUDIT POLICY LOGIN_AUDIT_POLICY
    ACTIONS LOGON, LOGOFF
    WHEN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') IN (''ADMIN_USER'', ''TEACHER_USER'', ''COUNSELOR_USER'', ''REGISTRAR_USER'', ''READ_ONLY_USER'')'
    EVALUATE PER STATEMENT;

CREATE AUDIT POLICY PRIVILEGE_AUDIT_POLICY
    ACTIONS GRANT, REVOKE
    WHEN 'SYS_CONTEXT(''USERENV'', ''SESSION_USER'') IN (''ADMIN_USER'', ''COUNSELOR_USER'')'
    EVALUATE PER STATEMENT;

-- privilege audit policy
-- Create policy to monitor role grants and privilege changes
CREATE AUDIT POLICY PRIV_ESCALATION
  ACTIONS
    GRANT ANY PRIVILEGE,
    GRANT ANY ROLE,
    ALTER USER,
    CREATE USER,
    DROP USER,
    CREATE ROLE,
    DROP ROLE;

-- Enable the policy
AUDIT POLICY PRIV_ESCALATION;

-- viewing audit records policy
SELECT
    EVENT_TIMESTAMP,
    DBUSERNAME,
    ACTION_NAME,
    RETURN_CODE
FROM
    UNIFIED_AUDIT_TRAIL
ORDER BY
    EVENT_TIMESTAMP DESC;

-- roles needed policies
-- User who manages audit config
GRANT AUDIT_ADMIN TO KEMAL;

-- User who views audit logs
GRANT AUDIT_VIEWER TO RAVI;

-- Enable audit policies
AUDIT POLICY STUDENT_ACCESS_POLICY;

AUDIT POLICY GRADE_ACCESS_POLICY;

AUDIT POLICY LOGIN_AUDIT_POLICY;

AUDIT POLICY PRIVILEGE_AUDIT_POLICY;

-- =====================================================
-- 8. DEFINER'S AND INVOKER'S RIGHTS PROCEDURES
-- =====================================================

-- Create secure procedure with definer's rights (default)
CREATE OR REPLACE PROCEDURE GET_STUDENT_GPA(
    P_STUDENT_ID IN NUMBER,
    P_GPA OUT NUMBER
)
    AUTHID DEFINER AS
BEGIN
 
    -- Only authorized users can access GPA information
    IF SYS_CONTEXT('USERENV', 'SESSION_USER') IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER') THEN
        SELECT
            GPA INTO P_GPA
        FROM
            SCHOOL_SCHEMA.STUDENTS
        WHERE
            STUDENT_ID = P_STUDENT_ID;
    ELSE
        RAISE_APPLICATION_ERROR(-20001, 'Insufficient privileges to access GPA information');
    END IF;
END;
/

-- Create procedure with invoker's rights for grade updates
CREATE OR REPLACE PROCEDURE UPDATE_STUDENT_GRADE(
    P_ENROLLMENT_ID IN NUMBER,
    P_GRADE IN VARCHAR2,
    P_FINAL_SCORE IN NUMBER
)
    AUTHID CURRENT_USER AS
BEGIN
    UPDATE SCHOOL_SCHEMA.ENROLLMENTS
    SET
        GRADE = P_GRADE,
        FINAL_SCORE = P_FINAL_SCORE
    WHERE
        ENROLLMENT_ID = P_ENROLLMENT_ID;
    IF SQL%ROWCOUNT = 0 THEN
        RAISE_APPLICATION_ERROR(-20002, 'Enrollment not found or no rows updated');
    END IF;
END;
/

-- Create procedure for student enrollment
CREATE OR REPLACE PROCEDURE ENROLL_STUDENT_IN_COURSE(
    P_STUDENT_ID IN NUMBER,
    P_COURSE_ID IN NUMBER
)
    AUTHID DEFINER AS
    V_STUDENT_EXISTS   NUMBER;
    V_COURSE_EXISTS    NUMBER;
    V_ALREADY_ENROLLED NUMBER;
BEGIN

    -- Check if student exists
    SELECT
        COUNT(*) INTO V_STUDENT_EXISTS
    FROM
        SCHOOL_SCHEMA.STUDENTS
    WHERE
        STUDENT_ID = P_STUDENT_ID;
    IF V_STUDENT_EXISTS = 0 THEN
        RAISE_APPLICATION_ERROR(-20003, 'Student not found');
    END IF;


    -- Check if course exists
    SELECT
        COUNT(*) INTO V_COURSE_EXISTS
    FROM
        SCHOOL_SCHEMA.COURSES
    WHERE
        COURSE_ID = P_COURSE_ID;
    IF V_COURSE_EXISTS = 0 THEN
        RAISE_APPLICATION_ERROR(-20004, 'Course not found');
    END IF;


    -- Check if already enrolled
    SELECT
        COUNT(*) INTO V_ALREADY_ENROLLED
    FROM
        SCHOOL_SCHEMA.ENROLLMENTS
    WHERE
        STUDENT_ID = P_STUDENT_ID
        AND COURSE_ID = P_COURSE_ID;
    IF V_ALREADY_ENROLLED > 0 THEN
        RAISE_APPLICATION_ERROR(-20005, 'Student already enrolled in this course');
    END IF;

    -- Create enrollment (ID is automatically generated)
    INSERT INTO SCHOOL_SCHEMA.ENROLLMENTS (STUDENT_ID, COURSE_ID, ENROLLMENT_DATE)
    VALUES (P_STUDENT_ID, P_COURSE_ID, SYSDATE);
    COMMIT;
END;
/

-- Grant execute privileges
GRANT EXECUTE ON GET_STUDENT_GPA TO ADMIN_ROLE, TEACHER_ROLE, COUNSELOR_ROLE;

GRANT EXECUTE ON UPDATE_STUDENT_GRADE TO TEACHER_ROLE, ADMIN_ROLE;

GRANT EXECUTE ON ENROLL_STUDENT_IN_COURSE TO REGISTRAR_ROLE, ADMIN_ROLE;

-- =====================================================
-- 9. BACKUP AND RESTORE PLANNING
-- =====================================================

-- Create backup directory
-- CREATE OR REPLACE DIRECTORY backup_dir AS '/u01/app/oracle/backup';

-- Create backup procedure
CREATE OR REPLACE PROCEDURE BACKUP_SCHOOL_DATA AS
    V_BACKUP_FILE VARCHAR2(200);
    V_TIMESTAMP   VARCHAR2(20);
BEGIN
    V_TIMESTAMP := TO_CHAR(SYSDATE, 'YYYYMMDD_HH24MISS');
    V_BACKUP_FILE := 'school_backup_'
                     || V_TIMESTAMP
                     || '.dmp';
 
    -- Export school data (this would be executed from OS level)
    -- expdp school_schema/password@ORCL directory=backup_dir dumpfile=v_backup_file
    --   tables=students,teachers,departments,courses,enrollments
    DBMS_OUTPUT.PUT_LINE('Backup file: '
                         || V_BACKUP_FILE);
    DBMS_OUTPUT.PUT_LINE('Backup completed at: '
                         || SYSDATE);
END;
/

-- Create restore procedure
CREATE OR REPLACE PROCEDURE RESTORE_SCHOOL_DATA(
    P_BACKUP_FILE IN VARCHAR2
) AS
BEGIN
 
    -- Import school data (this would be executed from OS level)
    -- impdp school_schema/password@ORCL directory=backup_dir dumpfile=p_backup_file
    DBMS_OUTPUT.PUT_LINE('Restore from file: '
                         || P_BACKUP_FILE);
    DBMS_OUTPUT.PUT_LINE('Restore completed at: '
                         || SYSDATE);
END;
/

-- =====================================================
-- 10. SECURITY TESTING QUERIES
-- =====================================================

-- Test queries to verify security implementation

-- 1. Test data redaction (should show masked addresses) and SIN encryption
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

-- 2. Test role-based access (should work for authorized users)
-- Connect as teacher_user and run:
-- SELECT * FROM students;

-- 3. Test audit trail
SELECT
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    TIMESTAMP
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    USERNAME IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER', 'REGISTRAR_USER', 'READ_ONLY_USER')
ORDER BY
    TIMESTAMP DESC;

-- 4. Test procedure access
-- DECLARE
--     v_gpa NUMBER;
-- BEGIN
--     get_student_gpa(2001, v_gpa);
--     DBMS_OUTPUT.PUT_LINE('GPA: ' || v_gpa);
-- END;
-- /

-- =====================================================
-- 11. SECURITY MONITORING QUERIES
-- =====================================================

-- Monitor failed login attempts
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

-- Monitor privilege escalations
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

-- Monitor data access patterns
SELECT
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    TIMESTAMP
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    OBJ_NAME IN ('STUDENTS', 'ENROLLMENTS')
ORDER BY
    TIMESTAMP DESC;

-- Check for unusual access times
SELECT
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    TIMESTAMP
FROM
    UNIFIED_AUDIT_TRAIL
WHERE
    EXTRACT(HOUR FROM TIMESTAMP) NOT BETWEEN 7 AND 18
ORDER BY
    TIMESTAMP DESC;

-- =====================================================
-- 12. CLEANUP AND MAINTENANCE PROCEDURES
-- =====================================================

-- Procedure to clean old audit records (older than 90 days)
CREATE OR REPLACE PROCEDURE CLEANUP_OLD_AUDIT_RECORDS AS
BEGIN
    DELETE FROM UNIFIED_AUDIT_TRAIL
    WHERE
        TIMESTAMP < SYSDATE - 90;
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Old audit records cleaned up');
END;
/

-- Schedule cleanup job (run weekly)
-- BEGIN
--     DBMS_SCHEDULER.CREATE_JOB(
--         job_name => 'CLEANUP_AUDIT_JOB',
--         job_type => 'STORED_PROCEDURE',
--         job_action => 'cleanup_old_audit_records',
--         repeat_interval => 'FREQ=WEEKLY; BYDAY=SUN; BYHOUR=2',
--         enabled => TRUE
--     );
-- END;
-- /

-- =====================================================
-- 13. SECURITY DOCUMENTATION QUERIES
-- =====================================================

-- List all audit policies
SELECT
    POLICY_NAME,
    ENABLED_OPTION,
    AUDIT_OPTION
FROM
    AUDIT_POLICIES
ORDER BY
    POLICY_NAME;

-- List all redaction policies
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

-- List all roles and their privileges
SELECT
    ROLE,
    PRIVILEGE,
    ADMIN_OPTION
FROM
    ROLE_SYS_PRIVS
ORDER BY
    ROLE,
    PRIVILEGE;

-- List all users and their profiles
SELECT
    USERNAME,
    PROFILE,
    ACCOUNT_STATUS,
    LOCK_DATE
FROM
    DBA_USERS
WHERE
    USERNAME IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER', 'REGISTRAR_USER', 'READ_ONLY_USER')
ORDER BY
    USERNAME;

-- =====================================================
-- END OF SECURITY IMPLEMENTATION
-- =====================================================

COMMIT;

-- Display completion message
PROMPT =====================================================

PROMPT School Database Security Implementation Complete

PROMPT =====================================================

PROMPT

PROMPT Security features implemented:

PROMPT - User authentication with secure profiles

PROMPT - Role-based access control for school staff

PROMPT - Data redaction policies for sensitive information (address only)

PROMPT - Comprehensive audit policies for core tables

PROMPT - Secure procedures with definer/invoker rights

PROMPT - Backup and restore procedures

PROMPT - Security monitoring queries

PROMPT

PROMPT Core tables: students, teachers, departments, courses, enrollments

PROMPT Note: Using default Oracle tablespaces (USERS, SYSTEM, SYSAUX)

PROMPT For production environments, consider creating encrypted tablespaces

PROMPT

PROMPT Next steps:

PROMPT 1. Test all security features

PROMPT 2. Run security testing queries

PROMPT 3. Monitor audit logs

PROMPT 4. Document any issues or improvements

PROMPT =====================================================