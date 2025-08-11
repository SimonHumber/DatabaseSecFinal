-- =====================================================
-- ORACLE WALLET/KEYSTORE SETUP FOR TDE ENCRYPTION
-- =====================================================
-- This script sets up Oracle Wallet for Transparent Data Encryption (TDE)
-- Required for column-level encryption (SIN columns) to work properly
-- =====================================================

-- Connect as SYSDBA to perform administrative tasks
-- CONNECT / AS SYSDBA;

-- =====================================================
-- 1. CREATE WALLET DIRECTORY
-- =====================================================

-- Create wallet directory (adjust path as needed for your system)
-- For Linux/Unix: /u01/app/oracle/admin/ORCL/wallet
-- For Windows: C:\oracle\admin\ORCL\wallet

-- Note: Create this directory manually or use OS commands:
-- For Windows: mkdir C:\oracle\admin\ORCL\wallet

-- =====================================================
-- 2. CONFIGURE WALLET LOCATION
-- =====================================================

-- Set wallet location in database
ALTER SYSTEM SET WALLET_ROOT = 'C:\oracle\admin\ORCL\wallet' SCOPE = SPFILE;

-- Set TDE configuration
ALTER SYSTEM SET TDE_CONFIGURATION = 'KEYSTORE_CONFIGURATION=FILE' SCOPE = BOTH;

-- =====================================================
-- 3. CREATE AND OPEN WALLET
-- =====================================================

-- Create wallet (this will prompt for password)
ADMINISTER KEY MANAGEMENT CREATE KEYSTORE 'C:\oracle\admin\ORCL\wallet' IDENTIFIED BY "WalletPass123!";

-- Open wallet
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "WalletPass123!";

-- =====================================================
-- 4. CREATE MASTER ENCRYPTION KEY
-- =====================================================

-- Create master encryption key for TDE
ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "WalletPass123!" WITH BACKUP;

-- =====================================================
-- 5. VERIFY WALLET STATUS
-- =====================================================

-- Check wallet status
SELECT WRL_TYPE, WRL_PARAMETER, STATUS FROM V$ENCRYPTION_WALLET;

-- Check TDE configuration
SELECT * FROM V$ENCRYPTION_KEYS;

-- =====================================================
-- 6. ALTERNATIVE: SOFTWARE KEYSTORE (AUTOLOGIN)
-- =====================================================

-- For development/testing, you can use autologin wallet
-- This doesn't require password but is less secure

-- Create autologin wallet
-- ADMINISTER KEY MANAGEMENT CREATE LOCAL AUTO_LOGIN KEYSTORE FROM KEYSTORE 'C:\oracle\admin\ORCL\wallet' IDENTIFIED BY "WalletPass123!";

-- =====================================================
-- 7. WALLET MAINTENANCE COMMANDS
-- =====================================================

-- Backup wallet
-- ADMINISTER KEY MANAGEMENT BACKUP KEYSTORE 'C:\oracle\admin\ORCL\wallet' TO 'C:\backup\wallet_backup' IDENTIFIED BY "WalletPass123!";

-- Rotate master key (periodic maintenance)
-- ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "WalletPass123!" WITH BACKUP;

-- =====================================================
-- 8. TROUBLESHOOTING COMMANDS
-- =====================================================

-- Check if wallet is accessible
-- SELECT * FROM V$ENCRYPTION_WALLET;

-- Check encryption status of tables
-- SELECT TABLE_NAME, COLUMN_NAME, ENCRYPTION_ALG FROM USER_ENCRYPTED_COLUMNS;

-- Check tablespace encryption
-- SELECT TABLESPACE_NAME, ENCRYPTION FROM DBA_TABLESPACES;

-- =====================================================
-- IMPORTANT NOTES:
-- =====================================================

-- 1. WALLET PASSWORD: Keep the wallet password secure and documented
-- 2. BACKUP: Always backup the wallet before making changes
-- 3. PERMISSIONS: Ensure proper file permissions on wallet directory
-- 4. RESTART: Database restart may be required after wallet setup
-- 5. PRODUCTION: Use Hardware Security Module (HSM) for production

-- =====================================================
-- DEVELOPMENT SETUP (Simplified)
-- =====================================================

-- For development/testing, you can use these simplified commands:

-- 1. Create wallet directory
-- mkdir C:\oracle\admin\ORCL\wallet

-- 2. Set wallet location
-- ALTER SYSTEM SET WALLET_ROOT = 'C:\oracle\admin\ORCL\wallet' SCOPE = SPFILE;

-- 3. Restart database
-- SHUTDOWN IMMEDIATE;
-- STARTUP;

-- 4. Create and open wallet
-- ADMINISTER KEY MANAGEMENT CREATE KEYSTORE IDENTIFIED BY "WalletPass123!";
-- ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "WalletPass123!";
-- ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "WalletPass123!" WITH BACKUP;

-- =====================================================
-- END OF KEYSTORE SETUP
-- =====================================================

PROMPT =====================================================
PROMPT Oracle Wallet Setup Instructions
PROMPT =====================================================
PROMPT
PROMPT 1. Create wallet directory manually
PROMPT 2. Uncomment and run the wallet creation commands
PROMPT 3. Restart database if needed
PROMPT 4. Verify wallet status
PROMPT
PROMPT After wallet setup, column encryption will work properly
PROMPT =====================================================
