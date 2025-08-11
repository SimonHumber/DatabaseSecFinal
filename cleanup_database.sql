-- =====================================================
-- COMPREHENSIVE DATABASE CLEANUP SCRIPT
-- =====================================================
-- This script drops all objects created in the school database security implementation
-- WARNING: This will permanently delete all data and objects!
-- Run this script only when you want to completely remove the school database
-- =====================================================

-- Set up error handling
SET SERVEROUTPUT ON;
DECLARE
    v_count NUMBER := 0;
BEGIN
    DBMS_OUTPUT.PUT_LINE('Starting comprehensive database cleanup...');
    DBMS_OUTPUT.PUT_LINE('==========================================');
END;
/

-- =====================================================
-- 1. DROP AUDIT POLICIES
-- =====================================================

-- Drop audit policies
BEGIN
    -- Drop PRIV_ESCALATION policy
    BEGIN
        EXECUTE IMMEDIATE 'NOAUDIT POLICY PRIV_ESCALATION';
        EXECUTE IMMEDIATE 'DROP AUDIT POLICY PRIV_ESCALATION';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped PRIV_ESCALATION audit policy');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! PRIV_ESCALATION audit policy not found or already dropped');
    END;

    -- Drop PRIVILEGE_AUDIT_POLICY
    BEGIN
        EXECUTE IMMEDIATE 'NOAUDIT POLICY PRIVILEGE_AUDIT_POLICY';
        EXECUTE IMMEDIATE 'DROP AUDIT POLICY PRIVILEGE_AUDIT_POLICY';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped PRIVILEGE_AUDIT_POLICY');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! PRIVILEGE_AUDIT_POLICY not found or already dropped');
    END;

    -- Drop LOGIN_AUDIT_POLICY
    BEGIN
        EXECUTE IMMEDIATE 'NOAUDIT POLICY LOGIN_AUDIT_POLICY';
        EXECUTE IMMEDIATE 'DROP AUDIT POLICY LOGIN_AUDIT_POLICY';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped LOGIN_AUDIT_POLICY');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! LOGIN_AUDIT_POLICY not found or already dropped');
    END;

    -- Drop GRADE_ACCESS_POLICY
    BEGIN
        EXECUTE IMMEDIATE 'NOAUDIT POLICY GRADE_ACCESS_POLICY';
        EXECUTE IMMEDIATE 'DROP AUDIT POLICY GRADE_ACCESS_POLICY';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped GRADE_ACCESS_POLICY');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! GRADE_ACCESS_POLICY not found or already dropped');
    END;

    -- Drop STUDENT_ACCESS_POLICY
    BEGIN
        EXECUTE IMMEDIATE 'NOAUDIT POLICY STUDENT_ACCESS_POLICY';
        EXECUTE IMMEDIATE 'DROP AUDIT POLICY STUDENT_ACCESS_POLICY';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped STUDENT_ACCESS_POLICY');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! STUDENT_ACCESS_POLICY not found or already dropped');
    END;
END;
/

-- =====================================================
-- 2. DROP DATA REDACTION POLICIES
-- =====================================================

BEGIN
    -- Drop student address redaction policy
    BEGIN
        DBMS_REDACT.DROP_POLICY(
            object_schema => 'SCHOOL_SCHEMA',
            object_name => 'STUDENTS',
            policy_name => 'student_address_redaction'
        );
        DBMS_OUTPUT.PUT_LINE('✓ Dropped student_address_redaction policy');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! student_address_redaction policy not found or already dropped');
    END;
END;
/

-- =====================================================
-- 3. DROP STORED PROCEDURES
-- =====================================================

BEGIN
    -- Drop backup school data procedure
    BEGIN
        EXECUTE IMMEDIATE 'DROP PROCEDURE SCHOOL_SCHEMA.BACKUP_SCHOOL_DATA';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped BACKUP_SCHOOL_DATA procedure');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! BACKUP_SCHOOL_DATA procedure not found or already dropped');
    END;

    -- Drop restore school data procedure
    BEGIN
        EXECUTE IMMEDIATE 'DROP PROCEDURE SCHOOL_SCHEMA.RESTORE_SCHOOL_DATA';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped RESTORE_SCHOOL_DATA procedure');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! RESTORE_SCHOOL_DATA procedure not found or already dropped');
    END;

    -- Drop cleanup old audit records procedure
    BEGIN
        EXECUTE IMMEDIATE 'DROP PROCEDURE SCHOOL_SCHEMA.CLEANUP_OLD_AUDIT_RECORDS';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped CLEANUP_OLD_AUDIT_RECORDS procedure');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! CLEANUP_OLD_AUDIT_RECORDS procedure not found or already dropped');
    END;

    -- Drop get student GPA procedure
    BEGIN
        EXECUTE IMMEDIATE 'DROP PROCEDURE SCHOOL_SCHEMA.GET_STUDENT_GPA';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped GET_STUDENT_GPA procedure');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! GET_STUDENT_GPA procedure not found or already dropped');
    END;

    -- Drop update student grade procedure
    BEGIN
        EXECUTE IMMEDIATE 'DROP PROCEDURE SCHOOL_SCHEMA.UPDATE_STUDENT_GRADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped UPDATE_STUDENT_GRADE procedure');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! UPDATE_STUDENT_GRADE procedure not found or already dropped');
    END;

    -- Drop enroll student in course procedure
    BEGIN
        EXECUTE IMMEDIATE 'DROP PROCEDURE SCHOOL_SCHEMA.ENROLL_STUDENT_IN_COURSE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped ENROLL_STUDENT_IN_COURSE procedure');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! ENROLL_STUDENT_IN_COURSE procedure not found or already dropped');
    END;
END;
/

-- =====================================================
-- 4. DROP TABLES (in correct order due to dependencies)
-- =====================================================

BEGIN
    -- Drop enrollments table (has foreign keys to students and courses)
    BEGIN
        EXECUTE IMMEDIATE 'DROP TABLE SCHOOL_SCHEMA.ENROLLMENTS CASCADE CONSTRAINTS';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped ENROLLMENTS table');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! ENROLLMENTS table not found or already dropped');
    END;

    -- Drop courses table (has foreign keys to teachers and departments)
    BEGIN
        EXECUTE IMMEDIATE 'DROP TABLE SCHOOL_SCHEMA.COURSES CASCADE CONSTRAINTS';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped COURSES table');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! COURSES table not found or already dropped');
    END;

    -- Drop students table
    BEGIN
        EXECUTE IMMEDIATE 'DROP TABLE SCHOOL_SCHEMA.STUDENTS CASCADE CONSTRAINTS';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped STUDENTS table');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! STUDENTS table not found or already dropped');
    END;

    -- Drop teachers table (has foreign key to departments)
    BEGIN
        EXECUTE IMMEDIATE 'DROP TABLE SCHOOL_SCHEMA.TEACHERS CASCADE CONSTRAINTS';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped TEACHERS table');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! TEACHERS table not found or already dropped');
    END;

    -- Drop departments table
    BEGIN
        EXECUTE IMMEDIATE 'DROP TABLE SCHOOL_SCHEMA.DEPARTMENTS CASCADE CONSTRAINTS';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped DEPARTMENTS table');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! DEPARTMENTS table not found or already dropped');
    END;
END;
/

-- =====================================================
-- 5. REVOKE ROLE PRIVILEGES FROM USERS
-- =====================================================

BEGIN
    -- Revoke roles from users
    BEGIN
        EXECUTE IMMEDIATE 'REVOKE ADMIN_ROLE FROM ADMIN_USER';
        EXECUTE IMMEDIATE 'REVOKE TEACHER_ROLE FROM TEACHER_USER';
        EXECUTE IMMEDIATE 'REVOKE COUNSELOR_ROLE FROM COUNSELOR_USER';
        EXECUTE IMMEDIATE 'REVOKE REGISTRAR_ROLE FROM REGISTRAR_USER';
        EXECUTE IMMEDIATE 'REVOKE READ_ONLY_ROLE FROM READ_ONLY_USER';
        EXECUTE IMMEDIATE 'REVOKE AUDIT_ROLE FROM ADMIN_USER';
        EXECUTE IMMEDIATE 'REVOKE AUDIT_ROLE FROM COUNSELOR_USER';
        DBMS_OUTPUT.PUT_LINE('✓ Revoked all role assignments from users');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! Some role revocations failed: ' || SQLERRM);
    END;
END;
/

-- =====================================================
-- 6. DROP ROLES
-- =====================================================

BEGIN
    -- Drop roles
    BEGIN
        EXECUTE IMMEDIATE 'DROP ROLE ADMIN_ROLE';
        EXECUTE IMMEDIATE 'DROP ROLE TEACHER_ROLE';
        EXECUTE IMMEDIATE 'DROP ROLE COUNSELOR_ROLE';
        EXECUTE IMMEDIATE 'DROP ROLE REGISTRAR_ROLE';
        EXECUTE IMMEDIATE 'DROP ROLE READ_ONLY_ROLE';
        EXECUTE IMMEDIATE 'DROP ROLE AUDIT_ROLE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped all application roles');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! Some role drops failed: ' || SQLERRM);
    END;
END;
/

-- =====================================================
-- 7. DROP USERS
-- =====================================================

BEGIN
    -- Drop application users
    BEGIN
        EXECUTE IMMEDIATE 'DROP USER ADMIN_USER CASCADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped ADMIN_USER');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! ADMIN_USER not found or already dropped');
    END;

    BEGIN
        EXECUTE IMMEDIATE 'DROP USER TEACHER_USER CASCADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped TEACHER_USER');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! TEACHER_USER not found or already dropped');
    END;

    BEGIN
        EXECUTE IMMEDIATE 'DROP USER COUNSELOR_USER CASCADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped COUNSELOR_USER');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! COUNSELOR_USER not found or already dropped');
    END;

    BEGIN
        EXECUTE IMMEDIATE 'DROP USER REGISTRAR_USER CASCADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped REGISTRAR_USER');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! REGISTRAR_USER not found or already dropped');
    END;

    BEGIN
        EXECUTE IMMEDIATE 'DROP USER READ_ONLY_USER CASCADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped READ_ONLY_USER');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! READ_ONLY_USER not found or already dropped');
    END;

    -- Drop schema user last
    BEGIN
        EXECUTE IMMEDIATE 'DROP USER SCHOOL_SCHEMA CASCADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped SCHOOL_SCHEMA');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! SCHOOL_SCHEMA not found or already dropped');
    END;
END;
/

-- =====================================================
-- 8. DROP SECURITY PROFILE
-- =====================================================

BEGIN
    -- Drop secure profile
    BEGIN
        EXECUTE IMMEDIATE 'DROP PROFILE SECURE_PROFILE CASCADE';
        DBMS_OUTPUT.PUT_LINE('✓ Dropped SECURE_PROFILE');
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('! SECURE_PROFILE not found or already dropped');
    END;
END;
/

-- =====================================================
-- 9. CLEANUP COMPLETION
-- =====================================================

DECLARE
    v_count NUMBER := 0;
BEGIN
    DBMS_OUTPUT.PUT_LINE('');
    DBMS_OUTPUT.PUT_LINE('==========================================');
    DBMS_OUTPUT.PUT_LINE('DATABASE CLEANUP COMPLETED SUCCESSFULLY!');
    DBMS_OUTPUT.PUT_LINE('==========================================');
    DBMS_OUTPUT.PUT_LINE('');
    DBMS_OUTPUT.PUT_LINE('The following objects have been removed:');
    DBMS_OUTPUT.PUT_LINE('✓ All audit policies');
    DBMS_OUTPUT.PUT_LINE('✓ All data redaction policies (address redaction only)');
    DBMS_OUTPUT.PUT_LINE('✓ All stored procedures');
    DBMS_OUTPUT.PUT_LINE('✓ All tables and data');
    DBMS_OUTPUT.PUT_LINE('✓ All application roles');
    DBMS_OUTPUT.PUT_LINE('✓ All application users');
    DBMS_OUTPUT.PUT_LINE('✓ Security profile');
    DBMS_OUTPUT.PUT_LINE('');
    DBMS_OUTPUT.PUT_LINE('WARNING: All data has been permanently deleted!');
    DBMS_OUTPUT.PUT_LINE('If you need to restore, use your backup files.');
    DBMS_OUTPUT.PUT_LINE('');
END;
/

COMMIT;

-- =====================================================
-- END OF CLEANUP SCRIPT
-- =====================================================
