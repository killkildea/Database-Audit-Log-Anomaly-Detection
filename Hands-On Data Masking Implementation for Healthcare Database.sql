/*
Your challenge
	Design and implement column-level masking policies for the patient database
	that enable safe data sharing for analytics teams, application development,
	and external audit firms. The implementation must balance privacy protection
	with operational utility, ensuring that different user roles can access
	appropriate data views for their legitimate business functions.

Scope Clarification
	This assignment emphasizes core column-level masking concepts and
	implementation. Advanced performance tuning, multi-environment
	orchestration, and detailed regulatory mappings remain included below but are
	considered secondary and may be treated as optional extensions for this
	submission

Learning Focus
You will demonstrate these capabilities:
	-Configure column-level masking policies for multiple sensitive data types SSN, medical record numbers, addresses)
	-Validate masking effectiveness across different user role scenarios
	-Analyze the impact of masking on data utility and application functionality
		-Create documentation that explains masking strategy and implementation decisions

Submission Requirement:
	The first two capabilities are required. Impact analysis and documentation may be concise and high-level

Database Setup:
	Create a patient table with these columns:
		PatientID (Primary Key)
		FirstName, LastName
		SSN (Social Security Number)
		DateOfBirth
		MedicalRecordNumber
		EmailAddress
		PhoneNumber
		StreetAddress, City, State, ZipCode
		InsuranceID

A standardized sample dataset and data dictionary are provided to ensure consistent, reproducible masking implementations across learners.

STANDARDIZED SAMPLE DATASET AND DATA DICTIONARY

Database Schema Creation Script

MedSecure Healthcare – SQL Server (2016+) DDM Lab Script

Creates DB + Patient table
Loads sample data
Creates 3 users for testing
Applies Dynamic Data Masking (DDM)
Grants UNMASK only to AuditUser (example)
Includes validation queries using EXECUTE AS

*/


-- 1) Database + Table
	IF DB_ID('MedSecureHealthcare') IS NULL
	CREATE DATABASE MedSecureHealthcare;
	GO
	USE MedSecureHealthcare;
	GO
	IF OBJECT_ID('dbo.Patient', 'U') IS NOT NULL
	DROP TABLE dbo.Patient;
	GO


	CREATE TABLE dbo.Patient (
	PatientID INT IDENTITY(1,1) PRIMARY KEY,
	FirstName NVARCHAR(50) NOT NULL,
	LastName NVARCHAR(50) NOT NULL,
	SSN NVARCHAR(11) NOT NULL,
	DateOfBirth DATE NOT NULL,
	MedicalRecordNumber NVARCHAR(10) NOT NULL UNIQUE,
	EmailAddress NVARCHAR(100) NULL,
	PhoneNumber NVARCHAR(15) NULL,
	StreetAddress NVARCHAR(200) NULL,
	City NVARCHAR(50) NULL,
	State NVARCHAR(2) NULL,
	ZipCode NVARCHAR(10) NULL,
	InsuranceID NVARCHAR(20) NULL
);

--2) Sample Data Load (15 rows)
	INSERT INTO dbo.Patient
	(FirstName, LastName, SSN, DateOfBirth, MedicalRecordNumber,
	EmailAddress, PhoneNumber,
	StreetAddress, City, State, ZipCode, InsuranceID)
	VALUES
	('Jennifer','Smith','123-45-6789','1985-03-15','MRN2001001','jennifer.smith@email.com','555-123-4567','123 Oak Street','Springfield','IL','62701','BC-789456123'),
	('Michael','Johnson','234-56-7890','1978-07-22','MRN2001002','mjohnson@gmail.com','555-234-5678','456 Maple Avenue','Chicago','IL','60601','AE-456789012'),
	('Sarah','Williams','345-67-8901','1992-11-08','MRN2001003','sarah.williams@yahoo.com','555-345-6789','789 Pine Boulevard','Peoria','IL','61601','UH-123456789'),
	('David','Brown','456-78-9012','1965-01-30','MRN2001004','dbrown@hotmail.com','555-456-7890','321 Cedar Lane','Rockford','IL','61101','BC-987654321'),
	('Lisa','Davis','567-89-0123','1989-09-14','MRN2001005','lisa.davis@outlook.com','555-567-8901','654 Birch Circle','Springfield','IL','62702','AE-234567890'),
	('Robert','Miller','678-90-1234','1973-05-03','MRN2001006','rmiller@email.com','555-678-9012','987 Willow Drive','Champaign','IL','61820','UH-345678901'),
	('Amanda','Wilson','789-01-2345','1981-12-19','MRN2001007','amanda.wilson@gmail.com','555-789-0123','147 Elm Street','Decatur','IL','62521','BC-456789123'),
	('Christopher','Moore','890-12-3456','1970-08-27','MRN2001008','cmoore@yahoo.com','555-890-1234','258 Ash Avenue','Bloomington','IL','61701','AE-567890234'),
	('Michelle','Taylor','901-23-4567','1995-02-11','MRN2001009','mtaylor@hotmail.com','555-901-2345','369 Spruce Lane','Normal','IL','61761','UH-678901345'),
	('James','Anderson','012-34-5678','1963-06-16','MRN2001010','janderson@outlook.com','555-012-3456','741 Poplar Court','Springfield','IL','62703','BC-789012456'),
	('Emily','Thomas','123-45-6780','1987-04-08','MRN2001011','emily.thomas@email.com','555-123-4568','852 Hickory Road','Chicago','IL','60602','AE-890123567'),
	('Daniel','Jackson','234-56-7891','1976-10-25','MRN2001012','djackson@gmail.com','555-234-5679','963 Walnut Street','Peoria','IL','61602','UH-901234678'),
	('Jessica','White','345-67-8902','1990-07-04','MRN2001013','jwhite@yahoo.com','555-345-6780','174 Cherry Avenue','Rockford','IL','61102','BC-012345789'),
	('Matthew','Harris','456-78-9013','1968-12-31','MRN2001014','mharris@hotmail.com','555-456-7891','285 Sycamore Lane','Champaign','IL','61821','AE-123456890'),
	('Ashley','Martin','567-89-0124','1993-01-17','MRN2001015','ashley.martin@outlook.com','555-567-8902','396 Dogwood Circle','Decatur','IL','62522','UH-234567901');
	GO

	--3) Users (no logins) + Permissions
	IF USER_ID('AnalyticsUser') IS NULL CREATE USER AnalyticsUser
	WITHOUT LOGIN;
	IF USER_ID('DevelopmentUser') IS NULL CREATE USER
	DevelopmentUser WITHOUT LOGIN;
	IF USER_ID('AuditUser') IS NULL CREATE USER AuditUser
	WITHOUT LOGIN;
	GO

	GRANT SELECT ON dbo.Patient TO AnalyticsUser;
	GRANT SELECT ON dbo.Patient TO DevelopmentUser;
	GRANT SELECT ON dbo.Patient TO AuditUser;
GO

--4) Dynamic Data Masking (supported SQL Server DDM functions)
--Note: DDM is NOT static substitution; keep it simple + valid High sensitivity
	ALTER TABLE dbo.Patient ALTER COLUMN SSN
	ADD MASKED WITH (FUNCTION = 'partial(0,"XXX-XX-",4)');
	GO
	ALTER TABLE dbo.Patient ALTER COLUMN MedicalRecordNumber
	ADD MASKED WITH (FUNCTION = 'partial(0,"MRNXXXX",2)'); -- shows last 2 chars only
	GO

--Medium sensitivity
	ALTER TABLE dbo.Patient ALTER COLUMN EmailAddress
	ADD MASKED WITH (FUNCTION = 'email()');
	GO
	ALTER TABLE dbo.Patient ALTER COLUMN PhoneNumber
	ADD MASKED WITH (FUNCTION = 'partial(0,"XXX-XXX-",4)'); -- last 4 only
	GO

	ALTER TABLE dbo.Patient ALTER COLUMN StreetAddress
	ADD MASKED WITH (FUNCTION = 'default()');
	GO
	ALTER TABLE dbo.Patient ALTER COLUMN ZipCode
	ADD MASKED WITH (FUNCTION = 'partial(0,"XXX",2)'); -- shows last 2 only
	GO

	--Names (DDM cannot do realistic substitution; mask with partial/default)
	ALTER TABLE dbo.Patient ALTER COLUMN FirstName
	ADD MASKED WITH (FUNCTION = 'partial(1,"XXXX",0)');
	GO

	ALTER TABLE dbo.Patient ALTER COLUMN LastName
	ADD MASKED WITH (FUNCTION = 'partial(1,"XXXX",0)');
	GO
	--DOB: DDM can't produce “age bands”; you can mask the exact date
	ALTER TABLE dbo.Patient ALTER COLUMN DateOfBirth
	ADD MASKED WITH (FUNCTION = 'default()');
GO

--5) UNMASK Permission (example policy)
	--Give auditors full visibility; keep Analytics/Dev masked
	GRANT UNMASK TO AuditUser;
	--AnalyticsUser and DevelopmentUser do NOT get UNMASK (remainmasked)
	GO

--6) Validation: See output by role
	--As AnalyticsUser (masked)
	EXECUTE AS USER = 'AnalyticsUser';
	SELECT TOP 5
	PatientID, FirstName, LastName, SSN, MedicalRecordNumber,
	EmailAddress, PhoneNumber, StreetAddress, City, State, ZipCode,
	DateOfBirth
	FROM dbo.Patient
	ORDER BY PatientID;
	REVERT;
	GO

	--As DevelopmentUser (masked)
	EXECUTE AS USER = 'DevelopmentUser';
	SELECT TOP 5
	PatientID, FirstName, LastName, SSN, MedicalRecordNumber,
	EmailAddress, PhoneNumber, StreetAddress, City, State, ZipCode,
	DateOfBirth
	FROM dbo.Patient
	ORDER BY PatientID;
	REVERT;
	GO

	--As AuditUser (unmasked)
	EXECUTE AS USER = 'AuditUser';
	SELECT TOP 5
	PatientID, FirstName, LastName, SSN, MedicalRecordNumber,
	EmailAddress, PhoneNumber, StreetAddress, City, State, ZipCode,
	DateOfBirth
	FROM dbo.Patient
	ORDER BY PatientID;
	REVERT;
	GO

--7) Analytics-friendly queries (work even when masked)
--Note: DateOfBirth is masked for non-UNMASK users, so age bucketing should be run by authorized users OR use a derived non-sensitive field.

	--Patient count by state (works for all)
	SELECT State, COUNT(*) AS PatientCount
	FROM dbo.Patient
	GROUP BY State;
	GO

	--Insurance carrier distribution (works for all)
	SELECT LEFT(InsuranceID, 2) AS InsuranceCarrier, COUNT(*) AS
	PatientCount
	FROM dbo.Patient
	GROUP BY LEFT(InsuranceID, 2);
	GO

/*
Your Challenge
	MedSecure Healthcare has identified three distinct data access scenarios that require different masking approaches
	Analytics Team Access: Data scientists need demographic and treatment data for population health studies but shouldn't access individual identifiers
	Application Development: Developers require realistic test data that maintains referential integrity and format consistency
	External Audit Access: Third-party auditors need statistical validation capabilities without accessing personal identifiers
	Design masking policies that support all three scenarios while maintaining HIPAA compliance.

Step 1: Data Classification and Sensitivity Analysis
	Analyze the patient database columns and classify them by sensitivity level:
		-High Sensitivity: Direct identifiers that must be fully protected (SSN, MedicalRecordNumber)
		-Medium Sensitivity: Quasi-identifiers that need partial protection (Name, Address, Phone)
		-Low Sensitivity: Non-identifying information that may need format preservation (DateOfBirth ranges, ZipCode areas)
		Document your classification rationale and create a sensitivity matrix that	maps each column to appropriate masking functions.

Step 2: Role-Based Access Policy Design
	Create three user roles with different access requirements:
		-AnalyticsUser
		-DevelopmentUser
		-AuditUser
			For each role, specify which columns should be masked and which	masking functions to apply.

Step 3: Masking Policy Implementation
	Implement your masking policies using appropriate database commands
		-Configure partial masking for SSNs (show last 4 digits)
		-Implement email masking that preserves domain structure
		-Create address masking that maintains geographic regions
		-Apply date masking that preserves age ranges while protecting specific birthdates
		Test each policy by querying data as different user roles to validate
		masking behavior.

Step 4: Validation and Impact Assessment
	Execute test queries that validate
		Masking policies activate correctly for each user role
		Data relationships and referential integrity remain intact
		Statistical properties needed for analytics are preserved
		Application functionality can work with masked data formats
		Document any issues discovered and provide solutions or alternative
		approaches.


Success Indicators
All high-sensitivity columns are properly masked for unauthorized users
Analytics queries execute successfully on masked data without revealing individual identities
Development environments receive consistent, realistic test data
Audit procedures validate data quality without exposing personal information
Documentation clearly explains masking strategy and implementation decisions
	Performance benchmarking and deep compliance mapping are not required for core completion.

Common Pitfalls & Prevention
	Pitfall 1: Inconsistent Masking Across Related Columns
	Prevention: Test data relationships after applying masking to ensure referential integrity is maintained. Create validation queries that work with both masked and unmasked data.

	Pitfall 2: Masking Functions That Break Application Logic
	Prevention: Collaborate with application teams to confirm format expectations. Test critical application functions against masked data.

	Pitfall 3: Performance Impact from Complex Masking Functions
	Prevention: Benchmark before and after masking. Consider pre-computing masked values for frequently accessed datasets.
*/
