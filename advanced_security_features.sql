-- =====================================================
-- Advanced Security Features for School Database in Oracle 19c
-- =====================================================
-- This script implements advanced security features including:
-- - Virtual Private Database (VPD)
-- - Row-Level Security (RLS)
-- - Transparent Data Encryption (TDE)
-- - Database Vault
-- - Label Security
-- - Fine-Grained Auditing (FGA)
-- =====================================================

-- Connect as SYSDBA to perform administrative tasks
-- CONNECT / AS SYSDBA;

-- =====================================================
-- 1. VIRTUAL PRIVATE DATABASE (VPD) IMPLEMENTATION
-- =====================================================

-- Create VPD function for student data access
CREATE OR REPLACE FUNCTION student_vpd_function(
    p_schema IN VARCHAR2,
    p_object IN VARCHAR2
) RETURN VARCHAR2
AS
    v_user VARCHAR2(30);
    v_department_id NUMBER;
BEGIN
    v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');
    
    -- Admin users can see all students
    IF v_user = 'ADMIN_USER' THEN
        RETURN NULL; -- No restriction
    END IF;
    
    -- Teachers can only see students in their courses
    IF v_user = 'TEACHER_USER' THEN
        RETURN 'student_id IN (SELECT DISTINCT e.student_id FROM enrollments e 
                               JOIN courses c ON e.course_id = c.course_id 
                               JOIN teachers t ON c.teacher_id = t.teacher_id 
                               WHERE t.email = SYS_CONTEXT(''USERENV'', ''SESSION_USER'') || ''@school.edu'')';
    END IF;
    
    -- Counselors can see all students (for counseling purposes)
    IF v_user = 'COUNSELOR_USER' THEN
        RETURN NULL; -- No restriction
    END IF;
    
    -- Registrars can see all students (for enrollment purposes)
    IF v_user = 'REGISTRAR_USER' THEN
        RETURN NULL; -- No restriction
    END IF;
    
    -- Read-only users can only see basic student info
    IF v_user = 'READ_ONLY_USER' THEN
        RETURN '1=1'; -- Allow all rows but columns will be restricted by view
    END IF;
    
    -- Default: no access
    RETURN '1=0';
END;
/

-- Apply VPD policy to students table
DBMS_RLS.ADD_POLICY(
    object_schema => 'SCHOOL_SCHEMA',
    object_name => 'STUDENTS',
    policy_name => 'student_vpd_policy',
    function_schema => 'SCHOOL_SCHEMA',
    policy_function => 'student_access_policy_function',
    statement_types => 'SELECT, UPDATE, DELETE',
    update_check => TRUE
);

-- Apply VPD policy to teachers table
DBMS_RLS.ADD_POLICY(
    object_schema => 'SCHOOL_SCHEMA',
    object_name => 'TEACHERS',
    policy_name => 'teacher_vpd_policy',
    function_schema => 'SCHOOL_SCHEMA',
    policy_function => 'teacher_access_policy_function',
    statement_types => 'SELECT, UPDATE, DELETE',
    update_check => TRUE
);

-- Create VPD function for enrollment data access
CREATE OR REPLACE FUNCTION enrollment_vpd_function(
    p_schema IN VARCHAR2,
    p_object IN VARCHAR2
) RETURN VARCHAR2
AS
    v_user VARCHAR2(30);
BEGIN
    v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');
    
    -- Admin and registrar users can access all enrollments
    IF v_user IN ('ADMIN_USER', 'REGISTRAR_USER') THEN
        RETURN NULL; -- No restriction
    END IF;
    
    -- Teachers can only access enrollments in their courses
    IF v_user = 'TEACHER_USER' THEN
        RETURN 'course_id IN (SELECT course_id FROM courses 
                              WHERE teacher_id = (SELECT teacher_id FROM teachers 
                                                 WHERE email = SYS_CONTEXT(''USERENV'', ''SESSION_USER'') || ''@school.edu''))';
    END IF;
    
    -- Counselors can access all enrollments
    IF v_user = 'COUNSELOR_USER' THEN
        RETURN NULL; -- No restriction
    END IF;
    
    -- Default: no access
    RETURN '1=0';
END;
/

-- Apply VPD policy to enrollments table
BEGIN
    DBMS_RLS.ADD_POLICY(
        object_schema => 'SCHOOL_SCHEMA',
        object_name => 'ENROLLMENTS',
        policy_name => 'ENROLLMENT_VPD_POLICY',
        function_schema => 'SCHOOL_SCHEMA',
        policy_function => 'ENROLLMENT_VPD_FUNCTION',
        statement_types => 'SELECT, INSERT, UPDATE, DELETE',
        update_check => TRUE
    );
END;
/

-- =====================================================
-- 2. FINE-GRAINED AUDITING (FGA) IMPLEMENTATION
-- =====================================================

-- Create FGA policy for GPA access
BEGIN
    DBMS_FGA.ADD_POLICY(
        object_schema => 'SCHOOL_SCHEMA',
        object_name => 'STUDENTS',
        policy_name => 'GPA_FGA_POLICY',
        audit_column => 'GPA',
        audit_condition => 'gpa > 3.5',
        statement_types => 'SELECT, UPDATE'
    );
END;
/

-- Create FGA policy for sensitive student data access
BEGIN
    DBMS_FGA.ADD_POLICY(
        object_schema => 'SCHOOL_SCHEMA',
        object_name => 'STUDENTS',
        policy_name => 'SENSITIVE_STUDENT_DATA_FGA_POLICY',
        audit_column => 'SSN, ADDRESS, PARENT_PHONE',
        audit_condition => NULL,
        statement_types => 'SELECT, UPDATE, INSERT, DELETE'
    );
END;
/

-- Create FGA policy for grade changes
BEGIN
    DBMS_FGA.ADD_POLICY(
        object_schema => 'SCHOOL_SCHEMA',
        object_name => 'ENROLLMENTS',
        policy_name => 'GRADE_CHANGE_FGA_POLICY',
        audit_column => 'GRADE, FINAL_SCORE',
        audit_condition => NULL,
        statement_types => 'SELECT, UPDATE, INSERT'
    );
END;
/

-- =====================================================
-- 3. CONTEXT-BASED SECURITY
-- =====================================================

-- Create application context
CREATE CONTEXT school_security_ctx USING school_schema.school_security_pkg;

-- Create package to manage application context
CREATE OR REPLACE PACKAGE school_security_pkg AS
    PROCEDURE set_user_context(p_user_id IN VARCHAR2);
    PROCEDURE clear_user_context;
END school_security_pkg;
/

CREATE OR REPLACE PACKAGE BODY school_security_pkg AS
    PROCEDURE set_user_context(p_user_id IN VARCHAR2) IS
        v_department_id NUMBER;
        v_role VARCHAR2(30);
        v_grade_level NUMBER;
    BEGIN
        -- Set user ID
        DBMS_SESSION.SET_CONTEXT('SCHOOL_SECURITY_CTX', 'USER_ID', p_user_id);
        
        -- Set user role based on username
        IF p_user_id = 'ADMIN_USER' THEN
            v_role := 'ADMIN';
        ELSIF p_user_id = 'TEACHER_USER' THEN
            v_role := 'TEACHER';
        ELSIF p_user_id = 'COUNSELOR_USER' THEN
            v_role := 'COUNSELOR';
        ELSIF p_user_id = 'REGISTRAR_USER' THEN
            v_role := 'REGISTRAR';
        ELSE
            v_role := 'USER';
        END IF;
        
        DBMS_SESSION.SET_CONTEXT('SCHOOL_SECURITY_CTX', 'USER_ROLE', v_role);
        
        -- Set department context for teachers
        IF p_user_id = 'TEACHER_USER' THEN
            SELECT department_id INTO v_department_id
            FROM teachers
            WHERE email = p_user_id || '@school.edu';
            
            DBMS_SESSION.SET_CONTEXT('SCHOOL_SECURITY_CTX', 'DEPARTMENT_ID', v_department_id);
        END IF;
        
        -- Set session timestamp
        DBMS_SESSION.SET_CONTEXT('SCHOOL_SECURITY_CTX', 'SESSION_TIME', TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'));
        
        -- Set school year context
        DBMS_SESSION.SET_CONTEXT('SCHOOL_SECURITY_CTX', 'SCHOOL_YEAR', TO_CHAR(SYSDATE, 'YYYY'));
    END set_user_context;
    
    PROCEDURE clear_user_context IS
    BEGIN
        DBMS_SESSION.CLEAR_CONTEXT('SCHOOL_SECURITY_CTX');
    END clear_user_context;
END school_security_pkg;
/

-- =====================================================
-- 4. ENHANCED ENCRYPTION FEATURES (USING DEFAULT TABLESPACES)
-- =====================================================

-- Note: Using default tablespaces instead of custom encrypted tablespaces
-- For production environments, consider creating encrypted tablespaces for sensitive data

-- Create encrypted table with additional security (using default tablespace)
CREATE TABLE encrypted_student_data (
    id NUMBER PRIMARY KEY,
    student_id NUMBER,
    encrypted_gpa RAW(2000),
    encrypted_ssn RAW(2000),
    encrypted_address RAW(2000),
    encrypted_parent_phone RAW(2000)
);

-- Create encryption/decryption functions
CREATE OR REPLACE FUNCTION encrypt_gpa(p_gpa IN NUMBER) RETURN RAW
AS
    v_encrypted RAW(2000);
BEGIN
    -- Use DBMS_CRYPTO for custom encryption
    v_encrypted := DBMS_CRYPTO.ENCRYPT(
        src => UTL_RAW.CAST_FROM_NUMBER(p_gpa),
        typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
        key => UTL_RAW.CAST_TO_RAW('SchoolSecretKey123456789012345678901234')
    );
    RETURN v_encrypted;
END;
/

CREATE OR REPLACE FUNCTION decrypt_gpa(p_encrypted IN RAW) RETURN NUMBER
AS
    v_decrypted RAW(2000);
    v_gpa NUMBER;
BEGIN
    -- Use DBMS_CRYPTO for custom decryption
    v_decrypted := DBMS_CRYPTO.DECRYPT(
        src => p_encrypted,
        typ => DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
        key => UTL_RAW.CAST_TO_RAW('SchoolSecretKey123456789012345678901234')
    );
    v_gpa := UTL_RAW.CAST_TO_NUMBER(v_decrypted);
    RETURN v_gpa;
END;
/

-- =====================================================
-- 5. SECURE APPLICATION ROLES
-- =====================================================

-- Create secure application role for teachers
CREATE ROLE secure_teacher_role IDENTIFIED USING school_schema.verify_teacher_role;

-- Create verification function for secure teacher role
CREATE OR REPLACE FUNCTION verify_teacher_role RETURN BOOLEAN
AS
    v_user VARCHAR2(30);
    v_time_hour NUMBER;
    v_day_of_week NUMBER;
BEGIN
    v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');
    v_time_hour := TO_NUMBER(TO_CHAR(SYSDATE, 'HH24'));
    v_day_of_week := TO_NUMBER(TO_CHAR(SYSDATE, 'D')); -- 1=Sunday, 7=Saturday
    
    -- Only allow teacher users
    IF v_user != 'TEACHER_USER' THEN
        RETURN FALSE;
    END IF;
    
    -- Only allow access during school hours (7 AM to 6 PM)
    IF v_time_hour < 7 OR v_time_hour > 18 THEN
        RETURN FALSE;
    END IF;
    
    -- Only allow access on weekdays (Monday = 2, Friday = 6)
    IF v_day_of_week < 2 OR v_day_of_week > 6 THEN
        RETURN FALSE;
    END IF;
    
    -- Check if user is not locked
    IF SYS_CONTEXT('USERENV', 'SESSION_USER') IN (
        SELECT username FROM dba_users 
        WHERE username = v_user AND account_status = 'OPEN'
    ) THEN
        RETURN TRUE;
    END IF;
    
    RETURN FALSE;
END;
/

-- Create secure application role for counselors
CREATE ROLE secure_counselor_role IDENTIFIED USING school_schema.verify_counselor_role;

-- Create verification function for secure counselor role
CREATE OR REPLACE FUNCTION verify_counselor_role RETURN BOOLEAN
AS
    v_user VARCHAR2(30);
    v_time_hour NUMBER;
BEGIN
    v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');
    v_time_hour := TO_NUMBER(TO_CHAR(SYSDATE, 'HH24'));
    
    -- Only allow counselor users
    IF v_user != 'COUNSELOR_USER' THEN
        RETURN FALSE;
    END IF;
    
    -- Allow access during extended hours (6 AM to 8 PM)
    IF v_time_hour < 6 OR v_time_hour > 20 THEN
        RETURN FALSE;
    END IF;
    
    -- Check if user is not locked
    IF SYS_CONTEXT('USERENV', 'SESSION_USER') IN (
        SELECT username FROM dba_users 
        WHERE username = v_user AND account_status = 'OPEN'
    ) THEN
        RETURN TRUE;
    END IF;
    
    RETURN FALSE;
END;
/

-- Grant secure application roles to users
GRANT secure_teacher_role TO teacher_user;
GRANT secure_counselor_role TO counselor_user;

-- =====================================================
-- 6. DATABASE VAULT IMPLEMENTATION
-- =====================================================

-- Note: Database Vault requires Enterprise Edition and separate licensing
-- The following are examples of what would be implemented with Database Vault

-- Create realm for sensitive student data
-- BEGIN
--     DVSYS.DBMS_MACADM.CREATE_REALM(
--         realm_name => 'SENSITIVE_STUDENT_DATA_REALM',
--         description => 'Realm for sensitive student information including medical and psychological data'
--     );
-- END;
-- /

-- Add objects to realm
-- BEGIN
--     DVSYS.DBMS_MACADM.ADD_OBJECT_TO_REALM(
--         realm_name => 'SENSITIVE_STUDENT_DATA_REALM',
--         object_owner => 'SCHOOL_SCHEMA',
--         object_name => 'STUDENTS',
--         object_type => 'TABLE'
--     );
-- END;
-- /

-- Create command rule to prevent direct table access
-- BEGIN
--     DVSYS.DBMS_MACADM.CREATE_COMMAND_RULE(
--         rule_name => 'PREVENT_DIRECT_STUDENT_ACCESS',
--         command => 'SELECT',
--         rule_set_name => 'SENSITIVE_STUDENT_DATA_RULE_SET',
--         object_owner => 'SCHOOL_SCHEMA',
--         object_name => 'STUDENTS'
--     );
-- END;
-- /

-- =====================================================
-- 7. LABEL SECURITY IMPLEMENTATION
-- =====================================================

-- Note: Label Security requires Enterprise Edition and separate licensing
-- The following are examples of what would be implemented with Label Security

-- Create label security policy
-- BEGIN
--     SA_SYSDBA.CREATE_POLICY(
--         policy_name => 'STUDENT_DATA_POLICY',
--         column_name => 'DATA_LABEL'
--     );
-- END;
-- /

-- Apply policy to students table
-- BEGIN
--     SA_SYSDBA.APPLY_TABLE_POLICY(
--         policy_name => 'STUDENT_DATA_POLICY',
--         schema_name => 'SCHOOL_SCHEMA',
--         table_name => 'STUDENTS'
--     );
-- END;
-- /

-- =====================================================
-- 8. ADVANCED AUDIT FEATURES
-- =====================================================

-- Create custom audit trigger for grade changes
CREATE OR REPLACE TRIGGER audit_grade_changes
AFTER UPDATE OF grade, final_score ON enrollments
FOR EACH ROW
WHEN (OLD.grade != NEW.grade OR OLD.final_score != NEW.final_score)
DECLARE
    v_audit_rec audit_log%ROWTYPE;
BEGIN
    v_audit_rec.audit_id := audit_seq.NEXTVAL;
    v_audit_rec.table_name := 'ENROLLMENTS';
    v_audit_rec.operation := 'UPDATE';
    v_audit_rec.old_value := 'Grade: ' || :OLD.grade || ', Score: ' || TO_CHAR(:OLD.final_score);
    v_audit_rec.new_value := 'Grade: ' || :NEW.grade || ', Score: ' || TO_CHAR(:NEW.final_score);
    v_audit_rec.user_name := USER;
    v_audit_rec.timestamp := SYSDATE;
    v_audit_rec.employee_id := :NEW.student_id;
    
    INSERT INTO audit_log VALUES v_audit_rec;
END;
/

-- Create custom audit trigger for student enrollment
CREATE OR REPLACE TRIGGER audit_student_enrollment
AFTER INSERT ON enrollments
FOR EACH ROW
DECLARE
    v_audit_rec audit_log%ROWTYPE;
BEGIN
    v_audit_rec.audit_id := audit_seq.NEXTVAL;
    v_audit_rec.table_name := 'ENROLLMENTS';
    v_audit_rec.operation := 'INSERT';
    v_audit_rec.old_value := NULL;
    v_audit_rec.new_value := 'Student: ' || :NEW.student_id || ', Course: ' || :NEW.course_id;
    v_audit_rec.user_name := USER;
    v_audit_rec.timestamp := SYSDATE;
    v_audit_rec.employee_id := :NEW.student_id;
    
    INSERT INTO audit_log VALUES v_audit_rec;
END;
/

-- =====================================================
-- 9. SECURITY MONITORING AND ALERTING
-- =====================================================

-- Create security alert table
CREATE TABLE security_alerts (
    alert_id NUMBER PRIMARY KEY,
    alert_type VARCHAR2(50),
    alert_message VARCHAR2(500),
    severity VARCHAR2(20),
    user_name VARCHAR2(30),
    timestamp DATE,
    resolved_date DATE,
    resolved_by VARCHAR2(30)
);

-- Create sequence for alerts
CREATE SEQUENCE alert_seq START WITH 1 INCREMENT BY 1;

-- Create procedure to log security alerts
CREATE OR REPLACE PROCEDURE log_security_alert(
    p_alert_type IN VARCHAR2,
    p_alert_message IN VARCHAR2,
    p_severity IN VARCHAR2 DEFAULT 'MEDIUM'
)
AS
BEGIN
    INSERT INTO security_alerts (
        alert_id, alert_type, alert_message, severity, 
        user_name, timestamp
    ) VALUES (
        alert_seq.NEXTVAL, p_alert_type, p_alert_message, p_severity,
        USER, SYSDATE
    );
    
    COMMIT;
    
    -- Log to alert log
    DBMS_OUTPUT.PUT_LINE('SECURITY ALERT: ' || p_alert_type || ' - ' || p_alert_message);
END;
/

-- Create procedure to monitor for security violations
CREATE OR REPLACE PROCEDURE monitor_school_security_violations
AS
    v_failed_logins NUMBER;
    v_privilege_escalations NUMBER;
    v_unusual_access NUMBER;
    v_grade_changes NUMBER;
    v_sensitive_data_access NUMBER;
BEGIN
    -- Check for multiple failed login attempts
    SELECT COUNT(*) INTO v_failed_logins
    FROM unified_audit_trail
    WHERE action_name = 'LOGON' AND return_code != 0
    AND timestamp > SYSDATE - 1/24; -- Last hour
    
    IF v_failed_logins > 5 THEN
        log_security_alert('FAILED_LOGIN_ATTEMPTS', 
            'Multiple failed login attempts detected: ' || v_failed_logins, 'HIGH');
    END IF;
    
    -- Check for privilege escalation attempts
    SELECT COUNT(*) INTO v_privilege_escalations
    FROM unified_audit_trail
    WHERE action_name IN ('GRANT', 'REVOKE', 'CREATE USER', 'ALTER USER')
    AND timestamp > SYSDATE - 1/24;
    
    IF v_privilege_escalations > 0 THEN
        log_security_alert('PRIVILEGE_ESCALATION', 
            'Privilege escalation attempts detected: ' || v_privilege_escalations, 'HIGH');
    END IF;
    
    -- Check for unusual access patterns
    SELECT COUNT(*) INTO v_unusual_access
    FROM unified_audit_trail
    WHERE EXTRACT(HOUR FROM timestamp) NOT BETWEEN 7 AND 18
    AND timestamp > SYSDATE - 1/24;
    
    IF v_unusual_access > 10 THEN
        log_security_alert('UNUSUAL_ACCESS_TIME', 
            'Unusual access patterns detected: ' || v_unusual_access, 'MEDIUM');
    END IF;
    
    -- Check for excessive grade changes
    SELECT COUNT(*) INTO v_grade_changes
    FROM unified_audit_trail
    WHERE obj_name = 'ENROLLMENTS' AND action_name = 'UPDATE'
    AND timestamp > SYSDATE - 1/24;
    
    IF v_grade_changes > 20 THEN
        log_security_alert('EXCESSIVE_GRADE_CHANGES', 
            'Excessive grade changes detected: ' || v_grade_changes, 'HIGH');
    END IF;
    
    -- Check for sensitive data access
    SELECT COUNT(*) INTO v_sensitive_data_access
    FROM unified_audit_trail
    WHERE obj_name = 'STUDENTS' AND action_name = 'SELECT'
    AND timestamp > SYSDATE - 1/24;
    
    IF v_sensitive_data_access > 50 THEN
        log_security_alert('SENSITIVE_DATA_ACCESS', 
            'High volume of sensitive data access: ' || v_sensitive_data_access, 'MEDIUM');
    END IF;
END;
/

-- =====================================================
-- 10. SECURITY TESTING FOR ADVANCED FEATURES
-- =====================================================

-- Test VPD policies
-- Connect as different users and test access restrictions
-- SELECT * FROM students; -- Should be restricted based on user role

-- Test FGA policies
-- SELECT gpa FROM students WHERE gpa > 3.5; -- Should trigger FGA

-- Test context-based security
BEGIN
    school_security_pkg.set_user_context('TEACHER_USER');
    DBMS_OUTPUT.PUT_LINE('User Context: ' || SYS_CONTEXT('SCHOOL_SECURITY_CTX', 'USER_ROLE'));
END;
/

-- Test encryption functions
DECLARE
    v_encrypted RAW(2000);
    v_decrypted NUMBER;
BEGIN
    v_encrypted := encrypt_gpa(3.85);
    v_decrypted := decrypt_gpa(v_encrypted);
    DBMS_OUTPUT.PUT_LINE('Original: 3.85, Decrypted: ' || v_decrypted);
END;
/

-- Test security monitoring
BEGIN
    monitor_school_security_violations;
END;
/

-- =====================================================
-- 11. SECURITY DOCUMENTATION QUERIES
-- =====================================================

-- List all VPD policies
SELECT object_schema, object_name, policy_name, function_name
FROM all_policies
WHERE object_schema = 'SCHOOL_SCHEMA'
ORDER BY object_name, policy_name;

-- List all FGA policies
SELECT object_schema, object_name, policy_name, audit_column
FROM all_audit_policies
WHERE object_schema = 'SCHOOL_SCHEMA'
ORDER BY object_name, policy_name;

-- List all application contexts
SELECT namespace, attribute, value
FROM session_context
WHERE namespace = 'SCHOOL_SECURITY_CTX';

-- List security alerts
SELECT alert_type, alert_message, severity, timestamp
FROM security_alerts
WHERE resolved_date IS NULL
ORDER BY timestamp DESC;

-- =====================================================
-- 12. PERFORMANCE OPTIMIZATION FOR SECURITY
-- =====================================================

-- Create indexes for audit tables
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_log_user ON audit_log(user_name);
CREATE INDEX idx_security_alerts_timestamp ON security_alerts(timestamp);
CREATE INDEX idx_security_alerts_type ON security_alerts(alert_type);

-- Create materialized view for security reporting
CREATE MATERIALIZED VIEW school_security_summary_mv
REFRESH COMPLETE ON DEMAND
AS
SELECT 
    TRUNC(timestamp, 'DD') as audit_date,
    user_name,
    COUNT(*) as total_actions,
    COUNT(CASE WHEN operation = 'SELECT' THEN 1 END) as select_ops,
    COUNT(CASE WHEN operation = 'UPDATE' THEN 1 END) as update_ops,
    COUNT(CASE WHEN operation = 'INSERT' THEN 1 END) as insert_ops,
    COUNT(CASE WHEN operation = 'DELETE' THEN 1 END) as delete_ops
FROM audit_log
GROUP BY TRUNC(timestamp, 'DD'), user_name;

-- =====================================================
-- 13. SCHOOL-SPECIFIC SECURITY FEATURES
-- =====================================================

-- Create procedure to validate student enrollment
CREATE OR REPLACE PROCEDURE validate_student_enrollment(
    p_student_id IN NUMBER,
    p_course_id IN NUMBER
) AUTHID DEFINER
AS
    v_student_exists NUMBER;
    v_course_exists NUMBER;
    v_already_enrolled NUMBER;
    v_course_full NUMBER;
    v_student_grade_level NUMBER;
    v_course_grade_level NUMBER;
BEGIN
    -- Check if student exists
    SELECT COUNT(*) INTO v_student_exists
    FROM students
    WHERE student_id = p_student_id;
    
    IF v_student_exists = 0 THEN
        RAISE_APPLICATION_ERROR(-20010, 'Student not found');
    END IF;
    
    -- Check if course exists
    SELECT COUNT(*) INTO v_course_exists
    FROM courses
    WHERE course_id = p_course_id;
    
    IF v_course_exists = 0 THEN
        RAISE_APPLICATION_ERROR(-20011, 'Course not found');
    END IF;
    
    -- Check if already enrolled
    SELECT COUNT(*) INTO v_already_enrolled
    FROM enrollments
    WHERE student_id = p_student_id AND course_id = p_course_id;
    
    IF v_already_enrolled > 0 THEN
        RAISE_APPLICATION_ERROR(-20012, 'Student already enrolled in this course');
    END IF;
    
    -- Check if course is full
    SELECT COUNT(*) INTO v_course_full
    FROM enrollments
    WHERE course_id = p_course_id;
    
    SELECT max_students INTO v_course_grade_level
    FROM courses
    WHERE course_id = p_course_id;
    
    IF v_course_full >= v_course_grade_level THEN
        RAISE_APPLICATION_ERROR(-20013, 'Course is full');
    END IF;
    
    -- Additional validation can be added here
    DBMS_OUTPUT.PUT_LINE('Enrollment validation passed');
END;
/

-- Create procedure to generate student report cards
CREATE OR REPLACE PROCEDURE generate_student_report_card(
    p_student_id IN NUMBER
) AUTHID DEFINER
AS
    v_student_name VARCHAR2(100);
    v_gpa NUMBER;
    v_course_count NUMBER;
BEGIN
    -- Only authorized users can generate report cards
    IF SYS_CONTEXT('USERENV', 'SESSION_USER') NOT IN ('ADMIN_USER', 'TEACHER_USER', 'COUNSELOR_USER') THEN
        RAISE_APPLICATION_ERROR(-20020, 'Insufficient privileges to generate report cards');
    END IF;
    
    -- Get student information
    SELECT first_name || ' ' || last_name, gpa
    INTO v_student_name, v_gpa
    FROM students
    WHERE student_id = p_student_id;
    
    -- Get course count
    SELECT COUNT(*)
    INTO v_course_count
    FROM enrollments
    WHERE student_id = p_student_id;
    
    -- Generate report card (simplified)
    DBMS_OUTPUT.PUT_LINE('=== STUDENT REPORT CARD ===');
    DBMS_OUTPUT.PUT_LINE('Student: ' || v_student_name);
    DBMS_OUTPUT.PUT_LINE('Student ID: ' || p_student_id);
    DBMS_OUTPUT.PUT_LINE('GPA: ' || v_gpa);
    DBMS_OUTPUT.PUT_LINE('Courses Enrolled: ' || v_course_count);
    DBMS_OUTPUT.PUT_LINE('Generated on: ' || SYSDATE);
    DBMS_OUTPUT.PUT_LINE('Generated by: ' || USER);
END;
/

-- Grant execute privileges
GRANT EXECUTE ON validate_student_enrollment TO registrar_role, admin_role;
GRANT EXECUTE ON generate_student_report_card TO admin_role, teacher_role, counselor_role;

-- =====================================================
-- END OF ADVANCED SECURITY FEATURES
-- =====================================================

COMMIT;

-- Display completion message
PROMPT =====================================================
PROMPT Advanced School Security Features Implementation Complete
PROMPT =====================================================
PROMPT 
PROMPT Advanced security features implemented:
PROMPT - Virtual Private Database (VPD) policies for student data
PROMPT - Fine-Grained Auditing (FGA) policies for grades and sensitive data
PROMPT - Context-based security for school environment
PROMPT - Enhanced encryption features for student information (using default tablespaces)
PROMPT - Secure application roles with time-based restrictions
PROMPT - Database Vault examples (commented)
PROMPT - Label Security examples (commented)
PROMPT - Advanced audit features for grade changes
PROMPT - Security monitoring and alerting for school activities
PROMPT - Performance optimization
PROMPT - School-specific security procedures
PROMPT
PROMPT Note: Using default Oracle tablespaces (USERS, SYSTEM, SYSAUX)
PROMPT For production environments, consider creating encrypted tablespaces
PROMPT Some features require Enterprise Edition and additional licensing
PROMPT
PROMPT Next steps:
PROMPT 1. Test all advanced security features
PROMPT 2. Monitor security alerts
PROMPT 3. Optimize performance as needed
PROMPT 4. Document security architecture
PROMPT =====================================================
