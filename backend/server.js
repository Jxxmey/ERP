// Core Modules
// -----------------------------------------------------
const express = require('express');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt'); // For password hashing
const jwt = require('jsonwebtoken'); // For JSON Web Tokens

// Load environment variables from .env file
dotenv.config();

// --- Debugging: Environment Variables Loaded ---
console.log('--- Environment Variables Loaded ---');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '********' : 'NOT SET');
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('PORT (App):', process.env.PORT);
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '********' : 'NOT SET');
console.log('SUPER_ADMIN_USERNAME:', process.env.SUPER_ADMIN_USERNAME);
console.log('SUPER_ADMIN_PASSWORD:', process.env.SUPER_ADMIN_PASSWORD ? '********' : 'NOT SET');
console.log('----------------------------------');
// --- End Debugging ---

// Initialize Express app and define port
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Ensure JWT_SECRET is set
if (!JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET is not defined in .env file. Please set it.');
    process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());

// -----------------------------------------------------
// Database Connection Pool
// -----------------------------------------------------
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('Connected to MySQL database successfully!');
        connection.release();
    })
    .catch(err => {
        console.error('Failed to connect to MySQL database:', err.message);
        process.exit(1);
    });

// -----------------------------------------------------
// Authentication & Authorization Middleware
// -----------------------------------------------------

/**
 * Middleware to authenticate JWT token from Authorization header.
 * Attaches user information (user_id, user_type, main_user_id, role_id, package_type, registration_status, trial_end_date) to req.user.
 */
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.status(401).json({ message: 'Authentication token required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        req.user = user; // user object contains { user_id, username, user_type, employee_id, main_user_id, role_id, package_type, registration_status, trial_end_date }
        next();
    });
}

/**
 * Middleware to authorize access for super_admin users only.
 */
function authorizeSuperAdmin(req, res, next) {
    if (req.user.user_type !== 'super_admin') {
        return res.status(403).json({ message: 'Access denied. Super Admin privileges required.' });
    }
    next();
}

/**
 * Middleware to authorize access for main users only.
 */
function authorizeMainUser(req, res, next) {
    if (req.user.user_type !== 'main' && req.user.user_type !== 'super_admin') { // Super admin can also act as main user
        return res.status(403).json({ message: 'Access denied. Main user privileges required.' });
    }
    next();
}

/**
 * Middleware to filter data based on main_user_id for employees and main users.
 * This middleware should be applied to routes that fetch/manage company-specific data.
 */
function authorizeDataOwner(req, res, next) {
    // If the user is a super_admin, they can access all data. No filtering needed.
    if (req.user.user_type === 'super_admin') {
        req.mainUserId = null; // No specific main_user_id filter for super_admin
        next();
        return;
    }

    // If the user is a main user, they own their data.
    if (req.user.user_type === 'main') {
        req.mainUserId = req.user.user_id;
    }
    // If the user is an employee, their data is tied to their main_user_id.
    else if (req.user.user_type === 'employee') {
        req.mainUserId = req.user.main_user_id;
    }
    // If mainUserId is not set (e.g., new user type or misconfiguration), deny access.
    if (!req.mainUserId) {
        return res.status(403).json({ message: 'Access denied. User context not established for data ownership.' });
    }
    next();
}

// -----------------------------------------------------
// API Routes
// -----------------------------------------------------

// Basic route for checking API status
app.get('/', (req, res) => {
    res.send('Welcome to the ERP/POS/HR Backend API!');
});

// -----------------------------------------------------
// Authentication Routes
// -----------------------------------------------------

// Register a new user (automatically 'approved' as 'main' and 'ทดลอง' package for 7 days)
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash password with salt rounds = 10

        // Calculate trial end date (7 days from now)
        const trialEndDate = new Date();
        trialEndDate.setDate(trialEndDate.getDate() + 7);
        const trialEndDateString = trialEndDate.toISOString().split('T')[0]; // Format as YYYY-MM-DD

        // Insert user with default 'approved' status, 'main' user_type, 'ทดลอง' package_type
        // and set main_user_id to their own user_id, and trial_end_date
        const [result] = await pool.query(
            'INSERT INTO Users (username, password_hash, registration_status, user_type, package_type, main_user_id, trial_end_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [username, hashedPassword, 'approved', 'main', 'ทดลอง', null, trialEndDateString] // main_user_id will be updated after insert
        );

        const newUserId = result.insertId;

        // Update main_user_id to self for main users
        await pool.query(
            'UPDATE Users SET main_user_id = ? WHERE user_id = ?',
            [newUserId, newUserId]
        );

        res.status(201).json({ message: 'Registration successful. Your trial period starts now.', userId: newUserId, trialEndDate: trialEndDateString });
    } catch (err) {
        console.error('Error during user registration:', err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username already exists.' });
        }
        res.status(500).json({ message: 'Internal server error during registration', error: err.message });
    }
});

// User login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const user = users[0];

        // Check password validity
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Check registration status
        if (user.registration_status === 'rejected') {
            return res.status(403).json({ message: 'Your account registration has been rejected. Please contact support.' });
        }

        // Check trial period for main users on trial package
        if (user.user_type === 'main' && user.package_type === 'ทดลอง' && user.trial_end_date) {
            const today = new Date();
            const trialEndDate = new Date(user.trial_end_date);
            // Set time to 00:00:00 for accurate date comparison
            today.setHours(0, 0, 0, 0);
            trialEndDate.setHours(0, 0, 0, 0);

            if (today > trialEndDate) {
                return res.status(403).json({ message: 'Your trial period has expired. Please upgrade your package to continue using the service.' });
            }
        }

        // Generate JWT token
        const tokenPayload = {
            user_id: user.user_id,
            username: user.username,
            user_type: user.user_type,
            employee_id: user.employee_id,
            // If main user, main_user_id is their own user_id. Otherwise, it's their assigned main_user_id.
            main_user_id: user.user_type === 'main' ? user.user_id : user.main_user_id,
            role_id: user.role_id,
            package_type: user.package_type,
            registration_status: user.registration_status,
            trial_end_date: user.trial_end_date ? user.trial_end_date.toISOString().split('T')[0] : null // Include trial end date in JWT
        };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour

        res.json({ message: 'Login successful', token: token, user: tokenPayload });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ message: 'Internal server error during login', error: err.message });
    }
});

// -----------------------------------------------------
// Super Admin Routes (Requires Super Admin privileges)
// -----------------------------------------------------

// Get all pending user registrations (will mostly be empty now, unless manually set to pending)
app.get('/api/admin/pending-users', authenticateToken, authorizeSuperAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT user_id, username, user_type, employee_id, main_user_id, role_id, package_type, registration_status, trial_end_date FROM Users WHERE registration_status = "pending"');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching pending users:', err);
        res.status(500).json({ message: 'Error fetching pending users', error: err.message });
    }
});

// Approve a user registration and set their type/package/main_user_id
// This endpoint is now primarily used by Super Admin to change a 'main' user's package
// or to assign an 'employee' user to a 'main' user.
app.put('/api/admin/approve-user/:id', authenticateToken, authorizeSuperAdmin, async (req, res) => {
    const { id } = req.params;
    const { user_type, employee_id, main_user_id, role_id, package_type } = req.body;

    // Fetch current user details to prevent unintended changes
    const [existingUsers] = await pool.query('SELECT user_id, user_type, registration_status FROM Users WHERE user_id = ?', [id]);
    if (existingUsers.length === 0) {
        return res.status(404).json({ message: 'User not found.' });
    }
    const existingUser = existingUsers[0];

    // Super admin can change registration_status to approved if it's not already
    let newRegistrationStatus = existingUser.registration_status;
    if (existingUser.registration_status === 'pending') {
        newRegistrationStatus = 'approved';
    }

    // Validate user_type
    if (!user_type || !['main', 'employee', 'super_admin'].includes(user_type)) {
        return res.status(400).json({ message: 'Valid user_type (main, employee, or super_admin) is required.' });
    }

    let updateFields = {
        user_type: user_type,
        registration_status: newRegistrationStatus,
        employee_id: null,
        main_user_id: null,
        role_id: null,
        package_type: null,
        trial_end_date: null // Reset trial_end_date if package_type is changed from 'ทดลอง'
    };

    if (user_type === 'main') {
        if (!package_type || !['ทดลอง', 'แพ็คเกจที่ 1', 'แพ็คเกจที่ 2', 'แพ็คเกจที่ 3'].includes(package_type)) {
            return res.status(400).json({ message: 'For main user, package_type is required and must be one of the predefined values.' });
        }
        updateFields.package_type = package_type;
        // If changing to 'ทดลอง' or keeping 'ทดลอง', ensure trial_end_date is set
        if (package_type === 'ทดลอง') {
            const trialEndDate = new Date();
            trialEndDate.setDate(trialEndDate.getDate() + 7);
            updateFields.trial_end_date = trialEndDate.toISOString().split('T')[0];
        }
        updateFields.main_user_id = id; // Main user's main_user_id is themselves
    } else if (user_type === 'employee') {
        if (!employee_id || !main_user_id || !role_id) {
            return res.status(400).json({ message: 'For employee user, employee_id, main_user_id, and role_id are required.' });
        }
        // Verify main_user_id actually exists and is a 'main' user
        try {
            const [mainUserCheck] = await pool.query('SELECT user_id FROM Users WHERE user_id = ? AND user_type = "main"', [main_user_id]);
            if (mainUserCheck.length === 0) {
                return res.status(400).json({ message: 'Provided main_user_id is invalid or not a main user.' });
            }
        } catch (err) {
            console.error('Error checking main_user_id:', err);
            return res.status(500).json({ message: 'Database error during main_user_id validation.', error: err.message });
        }
        updateFields.employee_id = employee_id;
        updateFields.main_user_id = main_user_id;
        updateFields.role_id = role_id;
    } else if (user_type === 'super_admin') {
        // Super admin doesn't have employee_id, main_user_id, role_id, package_type, trial_end_date
        updateFields.employee_id = null;
        updateFields.main_user_id = null;
        updateFields.role_id = null;
        updateFields.package_type = null;
        updateFields.trial_end_date = null;
    }

    try {
        const [result] = await pool.query(
            'UPDATE Users SET user_type = ?, registration_status = ?, employee_id = ?, main_user_id = ?, role_id = ?, package_type = ?, trial_end_date = ? WHERE user_id = ?',
            [updateFields.user_type, updateFields.registration_status, updateFields.employee_id, updateFields.main_user_id, updateFields.role_id, updateFields.package_type, updateFields.trial_end_date, id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found or no changes made.' });
        }
        res.json({ message: 'User updated successfully.' });
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ message: 'Internal server error during user update', error: err.message });
    }
});

// Reject a user registration (Super Admin can still reject, e.g., if a trial user violates terms)
app.put('/api/admin/reject-user/:id', authenticateToken, authorizeSuperAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query(
            'UPDATE Users SET registration_status = "rejected" WHERE user_id = ?',
            [id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found or already rejected.' });
        }
        res.json({ message: 'User registration rejected successfully.' });
    } catch (err) {
        console.error('Error rejecting user:', err);
        res.status(500).json({ message: 'Internal server error during user rejection', error: err.message });
    }
});

// -----------------------------------------------------
// Protected API Routes (Apply authenticateToken and authorizeDataOwner)
// These routes will now filter data based on the main_user_id associated with the logged-in user.
// Super Admin can see all data.
// -----------------------------------------------------

// Companies API
app.get('/api/companies', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM Companies';
        const params = [];
        if (req.mainUserId) { // If not super_admin, filter by main_user_id
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching companies:', err);
        res.status(500).json({ message: 'Error fetching companies', error: err.message });
    }
});

app.get('/api/companies/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM Companies WHERE company_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Company not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching company:', err);
        res.status(500).json({ message: 'Error fetching company', error: err.message });
    }
});

app.post('/api/companies', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { company_name, address, tax_id, phone, email } = req.body;
    if (!company_name) return res.status(400).json({ message: 'Company name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Companies (company_name, address, tax_id, phone, email, main_user_id) VALUES (?, ?, ?, ?, ?, ?)', [company_name, address, tax_id, phone, email, req.mainUserId]);
        res.status(201).json({ message: 'Company created successfully', companyId: result.insertId });
    } catch (err) {
        console.error('Error creating company:', err);
        res.status(500).json({ message: 'Error creating company', error: err.message });
    }
});

app.put('/api/companies/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { company_name, address, tax_id, phone, email } = req.body;
    try {
        const [result] = await pool.query('UPDATE Companies SET company_name = ?, address = ?, tax_id = ?, phone = ?, email = ? WHERE company_id = ? AND main_user_id = ?', [company_name, address, tax_id, phone, email, id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Company not found, not authorized, or no changes made' });
        res.json({ message: 'Company updated successfully' });
    } catch (err) {
        console.error('Error updating company:', err);
        res.status(500).json({ message: 'Error updating company', error: err.message });
    }
});

app.delete('/api/companies/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Companies WHERE company_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Company not found or not authorized' });
        res.json({ message: 'Company deleted successfully' });
    } catch (err) {
        console.error('Error deleting company:', err);
        res.status(500).json({ message: 'Error deleting company', error: err.message });
    }
});

// Branches API
app.get('/api/branches', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT b.* FROM Branches b JOIN Companies c ON b.company_id = c.company_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE c.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching branches:', err);
        res.status(500).json({ message: 'Error fetching branches', error: err.message });
    }
});

app.get('/api/branches/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT b.* FROM Branches b JOIN Companies c ON b.company_id = c.company_id WHERE b.branch_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND c.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Branch not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching branch:', err);
        res.status(500).json({ message: 'Error fetching branch', error: err.message });
    }
});

app.post('/api/branches', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { company_id, branch_name, address, phone } = req.body;
    if (!company_id || !branch_name) return res.status(400).json({ message: 'Company ID and branch name are required.' });

    try {
        const [companyRows] = await pool.query('SELECT company_id FROM Companies WHERE company_id = ? AND main_user_id = ?', [company_id, req.mainUserId]);
        if (companyRows.length === 0) {
            return res.status(403).json({ message: 'Company not found or not authorized for this main user.' });
        }

        const [result] = await pool.query('INSERT INTO Branches (company_id, branch_name, address, phone, main_user_id) VALUES (?, ?, ?, ?, ?)', [company_id, branch_name, address, phone, req.mainUserId]);
        res.status(201).json({ message: 'Branch created successfully', branchId: result.insertId });
    } catch (err) {
        console.error('Error creating branch:', err);
        res.status(500).json({ message: 'Error creating branch', error: err.message });
    }
});

app.put('/api/branches/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { company_id, branch_name, address, phone } = req.body;
    try {
        const [branchCheck] = await pool.query('SELECT b.branch_id FROM Branches b JOIN Companies c ON b.company_id = c.company_id WHERE b.branch_id = ? AND c.main_user_id = ?', [id, req.mainUserId]);
        if (branchCheck.length === 0) {
            return res.status(404).json({ message: 'Branch not found or not authorized.' });
        }

        if (company_id) {
            const [companyRows] = await pool.query('SELECT company_id FROM Companies WHERE company_id = ? AND main_user_id = ?', [company_id, req.mainUserId]);
            if (companyRows.length === 0) {
                return res.status(403).json({ message: 'Company not found or not authorized for this main user.' });
            }
        }

        const [result] = await pool.query('UPDATE Branches SET company_id = ?, branch_name = ?, address = ?, phone = ? WHERE branch_id = ? AND main_user_id = ?', [company_id, branch_name, address, phone, id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Branch not found, not authorized, or no changes made' });
        res.json({ message: 'Branch updated successfully' });
    } catch (err) {
        console.error('Error updating branch:', err);
        res.status(500).json({ message: 'Error updating branch', error: err.message });
    }
});

app.delete('/api/branches/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [branchCheck] = await pool.query('SELECT b.branch_id FROM Branches b JOIN Companies c ON b.company_id = c.company_id WHERE b.branch_id = ? AND c.main_user_id = ?', [id, req.mainUserId]);
        if (branchCheck.length === 0) {
            return res.status(404).json({ message: 'Branch not found or not authorized.' });
        }

        const [result] = await pool.query('DELETE FROM Branches WHERE branch_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Branch not found or not authorized' });
        res.json({ message: 'Branch deleted successfully' });
    } catch (err) {
        console.error('Error deleting branch:', err);
        res.status(500).json({ message: 'Error deleting branch', error: err.message });
    }
});

// Roles API (Accessible by main users, potentially global or company-specific roles)
app.get('/api/roles', authenticateToken, async (req, res) => {
    try {
        // Roles might be global or main-user specific. For now, assume global or filtered by main_user_id if roles table has it.
        // If roles are defined per main_user, uncomment and adjust query:
        // const [rows] = await pool.query('SELECT * FROM Roles WHERE main_user_id = ?', [req.mainUserId]);
        const [rows] = await pool.query('SELECT * FROM Roles'); // Assuming roles are global for simplicity for now
        res.json(rows);
    } catch (err) {
        console.error('Error fetching roles:', err);
        res.status(500).json({ message: 'Error fetching roles', error: err.message });
    }
});
// ... (other CRUD for Roles, Permissions, RolePermissions - adjust with authorizeMainUser if they are not global)

// Permissions API
app.get('/api/permissions', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Permissions');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching permissions:', err);
        res.status(500).json({ message: 'Error fetching permissions', error: err.message });
    }
});

app.get('/api/permissions/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Permissions WHERE permission_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Permission not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching permission:', err);
        res.status(500).json({ message: 'Error fetching permission', error: err.message });
    }
});

app.post('/api/permissions', authenticateToken, authorizeMainUser, async (req, res) => {
    const { permission_name, description } = req.body;
    if (!permission_name) return res.status(400).json({ message: 'Permission name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Permissions (permission_name, description) VALUES (?, ?)', [permission_name, description]);
        res.status(201).json({ message: 'Permission created successfully', permissionId: result.insertId });
    } catch (err) {
        console.error('Error creating permission:', err);
        res.status(500).json({ message: 'Error creating permission', error: err.message });
    }
});

app.put('/api/permissions/:id', authenticateToken, authorizeMainUser, async (req, res) => {
    const { id } = req.params;
    const { permission_name, description } = req.body;
    try {
        const [result] = await pool.query('UPDATE Permissions SET permission_name = ?, description = ? WHERE permission_id = ?', [permission_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Permission not found or no changes made' });
        res.json({ message: 'Permission updated successfully' });
    } catch (err) {
        console.error('Error updating permission:', err);
        res.status(500).json({ message: 'Error updating permission', error: err.message });
    }
});

app.delete('/api/permissions/:id', authenticateToken, authorizeMainUser, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Permissions WHERE permission_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Permission not found' });
        res.json({ message: 'Permission deleted successfully' });
    } catch (err) {
        console.error('Error deleting permission:', err);
        res.status(500).json({ message: 'Error deleting permission', error: err.message });
    }
});

// RolePermissions API
app.get('/api/rolepermissions', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT rp.role_id, r.role_name, rp.permission_id, p.permission_name FROM RolePermissions rp JOIN Roles r ON rp.role_id = r.role_id JOIN Permissions p ON rp.permission_id = p.permission_id');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching role permissions:', err);
        res.status(500).json({ message: 'Error fetching role permissions', error: err.message });
    }
});

app.post('/api/rolepermissions', authenticateToken, authorizeMainUser, async (req, res) => {
    const { role_id, permission_id } = req.body;
    if (!role_id || !permission_id) return res.status(400).json({ message: 'Role ID and Permission ID are required.' });
    try {
        const [result] = await pool.query('INSERT INTO RolePermissions (role_id, permission_id) VALUES (?, ?)', [role_id, permission_id]);
        res.status(201).json({ message: 'Role permission assigned successfully' });
    } catch (err) {
        console.error('Error assigning role permission:', err);
        res.status(500).json({ message: 'Error assigning role permission', error: err.message });
    }
});

app.delete('/api/rolepermissions', authenticateToken, authorizeMainUser, async (req, res) => {
    const { role_id, permission_id } = req.body;
    if (!role_id || !permission_id) return res.status(400).json({ message: 'Role ID and Permission ID are required.' });
    try {
        const [result] = await pool.query('DELETE FROM RolePermissions WHERE role_id = ? AND permission_id = ?', [role_id, permission_id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Role permission not found' });
        res.json({ message: 'Role permission removed successfully' });
    } catch (err) {
        console.error('Error removing role permission:', err);
        res.status(500).json({ message: 'Error removing role permission', error: err.message });
    }
});

// Departments API
app.get('/api/departments', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT d.* FROM Departments d';
        const params = [];
        if (req.mainUserId) {
            query += ' JOIN Employees e ON d.department_id = e.department_id WHERE e.main_user_id = ? GROUP BY d.department_id';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching departments:', err);
        res.status(500).json({ message: 'Error fetching departments', error: err.message });
    }
});

app.get('/api/departments/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT d.* FROM Departments d WHERE d.department_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND d.department_id IN (SELECT department_id FROM Employees WHERE main_user_id = ?)';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Department not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching department:', err);
        res.status(500).json({ message: 'Error fetching department', error: err.message });
    }
});

app.post('/api/departments', authenticateToken, authorizeMainUser, async (req, res) => {
    const { department_name } = req.body;
    if (!department_name) return res.status(400).json({ message: 'Department name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Departments (department_name) VALUES (?)', [department_name]);
        res.status(201).json({ message: 'Department created successfully', departmentId: result.insertId });
    } catch (err) {
        console.error('Error creating department:', err);
        res.status(500).json({ message: 'Error creating department', error: err.message });
    }
});

app.put('/api/departments/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { department_name } = req.body;
    try {
        // Ensure the department belongs to the main user's context if not super admin
        if (req.mainUserId) {
            const [departmentCheck] = await pool.query('SELECT d.department_id FROM Departments d JOIN Employees e ON d.department_id = e.department_id WHERE d.department_id = ? AND e.main_user_id = ? GROUP BY d.department_id', [id, req.mainUserId]);
            if (departmentCheck.length === 0) return res.status(404).json({ message: 'Department not found or not authorized.' });
        }

        const [result] = await pool.query('UPDATE Departments SET department_name = ? WHERE department_id = ?', [department_name, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Department not found or no changes made' });
        res.json({ message: 'Department updated successfully' });
    } catch (err) {
        console.error('Error updating department:', err);
        res.status(500).json({ message: 'Error updating department', error: err.message });
    }
});

app.delete('/api/departments/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        // Ensure the department belongs to the main user's context if not super admin
        if (req.mainUserId) {
            const [departmentCheck] = await pool.query('SELECT d.department_id FROM Departments d JOIN Employees e ON d.department_id = e.department_id WHERE d.department_id = ? AND e.main_user_id = ? GROUP BY d.department_id', [id, req.mainUserId]);
            if (departmentCheck.length === 0) return res.status(404).json({ message: 'Department not found or not authorized.' });
        }

        const [result] = await pool.query('DELETE FROM Departments WHERE department_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Department not found' });
        res.json({ message: 'Department deleted successfully' });
    } catch (err) {
        console.error('Error deleting department:', err);
        res.status(500).json({ message: 'Error deleting department', error: err.message });
    }
});

// Positions API
app.get('/api/positions', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT p.* FROM Positions p';
        const params = [];
        if (req.mainUserId) {
            query += ' JOIN Employees e ON p.position_id = e.position_id WHERE e.main_user_id = ? GROUP BY p.position_id';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching positions:', err);
        res.status(500).json({ message: 'Error fetching positions', error: err.message });
    }
});

app.get('/api/positions/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT p.* FROM Positions p WHERE p.position_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND p.position_id IN (SELECT position_id FROM Employees WHERE main_user_id = ?)';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Position not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching position:', err);
        res.status(500).json({ message: 'Error fetching position', error: err.message });
    }
});

app.post('/api/positions', authenticateToken, authorizeMainUser, async (req, res) => {
    const { position_name, description } = req.body;
    if (!position_name) return res.status(400).json({ message: 'Position name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Positions (position_name, description) VALUES (?, ?)', [position_name, description]);
        res.status(201).json({ message: 'Position created successfully', positionId: result.insertId });
    } catch (err) {
        console.error('Error creating position:', err);
        res.status(500).json({ message: 'Error creating position', error: err.message });
    }
});

app.put('/api/positions/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { position_name, description } = req.body;
    try {
        // Ensure the position belongs to the main user's context if not super admin
        if (req.mainUserId) {
            const [positionCheck] = await pool.query('SELECT p.position_id FROM Positions p JOIN Employees e ON p.position_id = e.position_id WHERE p.position_id = ? AND e.main_user_id = ? GROUP BY p.position_id', [id, req.mainUserId]);
            if (positionCheck.length === 0) return res.status(404).json({ message: 'Position not found or not authorized.' });
        }

        const [result] = await pool.query('UPDATE Positions SET position_name = ?, description = ? WHERE position_id = ?', [position_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Position not found or no changes made' });
        res.json({ message: 'Position updated successfully' });
    } catch (err) {
        console.error('Error updating position:', err);
        res.status(500).json({ message: 'Error updating position', error: err.message });
    }
});

app.delete('/api/positions/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        // Ensure the position belongs to the main user's context if not super admin
        if (req.mainUserId) {
            const [positionCheck] = await pool.query('SELECT p.position_id FROM Positions p JOIN Employees e ON p.position_id = e.position_id WHERE p.position_id = ? AND e.main_user_id = ? GROUP BY p.position_id', [id, req.mainUserId]);
            if (positionCheck.length === 0) return res.status(404).json({ message: 'Position not found or not authorized.' });
        }

        const [result] = await pool.query('DELETE FROM Positions WHERE position_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Position not found' });
        res.json({ message: 'Position deleted successfully' });
    } catch (err) {
        console.error('Error deleting position:', err);
        res.status(500).json({ message: 'Error deleting position', error: err.message });
    }
});


// Employees API (HR Module)
app.get('/api/employees', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM Employees';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching employees:', err);
        res.status(500).json({ message: 'Error fetching employees', error: err.message });
    }
});

app.get('/api/employees/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM Employees WHERE employee_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Employee not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching employee:', err);
        res.status(500).json({ message: 'Error fetching employee', error: err.message });
    }
});

app.post('/api/employees', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base } = req.body;
    if (!first_name || !last_name || !thai_id_no || !hire_date) return res.status(400).json({ message: 'First name, last name, Thai ID, and hire date are required.' });
    try {
        const [result] = await pool.query(
            'INSERT INTO Employees (user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base, main_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base, req.mainUserId]
        );
        res.status(201).json({ message: 'Employee created successfully', employeeId: result.insertId });
    } catch (err) {
        console.error('Error creating employee:', err);
        res.status(500).json({ message: 'Error creating employee', error: err.message });
    }
});

app.put('/api/employees/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE Employees SET user_id = ?, first_name = ?, last_name = ?, thai_id_no = ?, date_of_birth = ?, gender = ?, address = ?, phone = ?, email = ?, department_id = ?, position_id = ?, employment_status = ?, hire_date = ?, salary_base = ? WHERE employee_id = ? AND main_user_id = ?',
            [user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base, id, req.mainUserId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee not found, not authorized, or no changes made' });
        res.json({ message: 'Employee updated successfully' });
    } catch (err) {
        console.error('Error updating employee:', err);
        res.status(500).json({ message: 'Error updating employee', error: err.message });
    }
});

app.delete('/api/employees/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE Employees SET employment_status = "Terminated" WHERE employee_id = ? AND main_user_id = ?', [id, req.mainUserId]); // Soft delete
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee not found or not authorized' });
        res.json({ message: 'Employee terminated successfully (soft deleted)' });
    } catch (err) {
        console.error('Error terminating employee:', err);
        res.status(500).json({ message: 'Error terminating employee', error: err.message });
    }
});

// Users API (Admin/Main User Management)
// Note: This API is for main users to manage their employees/users. Super admin uses specific admin routes.
app.get('/api/users', authenticateToken, authorizeMainUser, async (req, res) => {
    try {
        let query = 'SELECT user_id, username, user_type, employee_id, main_user_id, role_id, package_type, registration_status, trial_end_date FROM Users';
        const params = [];
        if (req.user.user_type === 'main') {
            query += ' WHERE main_user_id = ? OR user_id = ?'; // Main user sees themselves and their employees
            params.push(req.user.user_id, req.user.user_id);
        } else if (req.user.user_type === 'employee') {
            // Employee can only see their own user record
            query += ' WHERE user_id = ?';
            params.push(req.user.user_id);
        }
        // Super admin sees all users (handled by authorizeSuperAdmin for admin routes)
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ message: 'Error fetching users', error: err.message });
    }
});

app.get('/api/users/:id', authenticateToken, authorizeMainUser, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT user_id, username, user_type, employee_id, main_user_id, role_id, package_type, registration_status, trial_end_date FROM Users WHERE user_id = ?';
        const params = [id];

        if (req.user.user_type === 'main') {
            query += ' AND (main_user_id = ? OR user_id = ?)';
            params.push(req.user.user_id, req.user.user_id);
        } else if (req.user.user_type === 'employee') {
            // Employee can only see their own user record
            if (parseInt(id) !== req.user.user_id) {
                return res.status(403).json({ message: 'Access denied. You can only view your own user record.' });
            }
        }

        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'User not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ message: 'Error fetching user', error: err.message });
    }
});

app.put('/api/users/:id', authenticateToken, authorizeMainUser, async (req, res) => {
    const { id } = req.params;
    const { username, password_hash, employee_id, role_id, registration_status, user_type, package_type } = req.body; // registration_status can be updated by main user for their employees
    try {
        // Main user can only update users under their control (or themselves)
        let userCheckQuery = 'SELECT user_id, user_type, main_user_id FROM Users WHERE user_id = ?';
        const userCheckParams = [id];

        if (req.user.user_type === 'main') {
            userCheckQuery += ' AND (main_user_id = ? OR user_id = ?)';
            userCheckParams.push(req.user.user_id, req.user.user_id);
        } else if (req.user.user_type === 'employee') {
            // Employee can only update their own user record
            if (parseInt(id) !== req.user.user_id) {
                return res.status(403).json({ message: 'Access denied. You can only update your own user record.' });
            }
        }

        const [userCheck] = await pool.query(userCheckQuery, userCheckParams);
        if (userCheck.length === 0) {
            return res.status(403).json({ message: 'Not authorized to update this user.' });
        }

        // Prevent main user from changing their own user_type or package_type
        if (parseInt(id) === req.user.user_id && userCheck[0].user_type === 'main' && (user_type || package_type)) {
            return res.status(403).json({ message: 'Main users cannot change their own user_type or package_type via this endpoint. Please contact Super Admin.' });
        }
        // Prevent main user from changing employee's user_type to main
        if (userCheck[0].user_type === 'employee' && user_type === 'main') {
            return res.status(403).json({ message: 'Cannot change an employee user to a main user via this endpoint.' });
        }

        // Only allow main user to update employee_id and role_id for their employees
        if (userCheck[0].user_type === 'employee' && userCheck[0].main_user_id === req.user.user_id) {
            // Allow update of employee_id and role_id for employees under this main user
        } else {
            // For other cases, disallow updating employee_id, role_id, user_type, package_type
            employee_id = undefined;
            role_id = undefined;
            user_type = undefined;
            package_type = undefined;
        }

        let hashedPassword = password_hash;
        if (password_hash) {
            hashedPassword = await bcrypt.hash(password_hash, 10);
        }

        const updateFields = {};
        if (username !== undefined) updateFields.username = username;
        if (hashedPassword !== undefined) updateFields.password_hash = hashedPassword;
        if (employee_id !== undefined) updateFields.employee_id = employee_id;
        if (role_id !== undefined) updateFields.role_id = role_id;
        if (registration_status !== undefined) updateFields.registration_status = registration_status;
        if (user_type !== undefined) updateFields.user_type = user_type;
        if (package_type !== undefined) updateFields.package_type = package_type;

        const updateKeys = Object.keys(updateFields);
        if (updateKeys.length === 0) {
            return res.status(400).json({ message: 'No fields provided for update.' });
        }

        const setClause = updateKeys.map(key => `${key} = ?`).join(', ');
        const updateValues = updateKeys.map(key => updateFields[key]);
        updateValues.push(id); // Add user_id for WHERE clause

        const [result] = await pool.query(
            `UPDATE Users SET ${setClause} WHERE user_id = ?`,
            updateValues
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found or no changes made' });
        res.json({ message: 'User updated successfully' });
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ message: 'Internal server error during user update', error: err.message });
    }
});

app.delete('/api/users/:id', authenticateToken, authorizeMainUser, async (req, res) => {
    const { id } = req.params;
    // Prevent main user from deleting themselves
    if (parseInt(id) === req.user.user_id) {
        return res.status(403).json({ message: 'Cannot deactivate your own main user account.' });
    }
    try {
        // Main user can deactivate users under their control
        const [result] = await pool.query('UPDATE Users SET registration_status = "rejected" WHERE user_id = ? AND main_user_id = ?', [id, req.user.user_id]); // Soft delete/deactivate
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found or not authorized to deactivate.' });
        res.json({ message: 'User deactivated successfully (status changed to rejected)' });
    } catch (err) {
        console.error('Error deactivating user:', err);
        res.status(500).json({ message: 'Error deactivating user', error: err.message });
    }
});

// AuditLogs API (Read-only, typically managed by system/triggers)
app.get('/api/auditlogs', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM AuditLogs';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE user_id IN (SELECT user_id FROM Users WHERE main_user_id = ? OR user_id = ?)';
            params.push(req.mainUserId, req.mainUserId);
        }
        query += ' ORDER BY timestamp DESC';
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching audit logs:', err);
        res.status(500).json({ message: 'Error fetching audit logs', error: err.message });
    }
});

app.get('/api/auditlogs/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM AuditLogs WHERE log_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND user_id IN (SELECT user_id FROM Users WHERE main_user_id = ? OR user_id = ?)';
            params.push(req.mainUserId, req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Audit log not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching audit log:', err);
        res.status(500).json({ message: 'Error fetching audit log', error: err.message });
    }
});


// --- POS Module Tables ---

// Products API
app.get('/api/products', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT p.* FROM Products p';
        const params = [];
        if (req.mainUserId) {
            // Products are not directly linked to main_user_id.
            // Assuming products are managed by main_user, so they should be available to all employees of that main user.
            // This query might need adjustment based on how products are truly scoped.
            // For now, if main_user_id is present, we assume products are accessible within that tenant.
            // A more robust solution might involve a `main_user_id` column in the `Products` table.
            // For demonstration, we'll fetch all products and assume they are relevant to the main user's context.
            // If products are created by main users, then they should have a main_user_id column.
            // Let's assume for now that products are created by main user and thus available to their employees.
            // If the Products table had a main_user_id column:
            // query += ' WHERE p.main_user_id = ?';
            // params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ message: 'Error fetching products', error: err.message });
    }
});

app.get('/api/products/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT p.* FROM Products p WHERE p.product_id = ?';
        const params = [id];
        if (req.mainUserId) {
            // Similar logic as above, assuming products are globally accessible or linked via other means.
            // If the Products table had a main_user_id column:
            // query += ' AND p.main_user_id = ?';
            // params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Product not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching product:', err);
        res.status(500).json({ message: 'Error fetching product', error: err.message });
    }
});

app.post('/api/products', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { product_code, product_name, category_id, unit_price, cost_price, stock_quantity, is_active } = req.body;
    if (!product_code || !product_name || !unit_price) {
        return res.status(400).json({ message: 'Product code, name, and unit price are required.' });
    }
    try {
        const [result] = await pool.query(
            'INSERT INTO Products (product_code, product_name, category_id, unit_price, cost_price, stock_quantity, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [product_code, product_name, category_id, unit_price, cost_price, stock_quantity, is_active]
        );
        res.status(201).json({ message: 'Product created successfully', productId: result.insertId });
    } catch (err) {
        console.error('Error creating product:', err);
        res.status(500).json({ message: 'Error creating product', error: err.message });
    }
});

app.put('/api/products/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { product_name, category_id, unit_price, cost_price, stock_quantity, is_active } = req.body;
    try {
        // If the Products table had a main_user_id column:
        // const [productCheck] = await pool.query('SELECT product_id FROM Products WHERE product_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        // if (productCheck.length === 0) {
        //     return res.status(404).json({ message: 'Product not found or not authorized.' });
        // }

        const [result] = await pool.query(
            'UPDATE Products SET product_name = ?, category_id = ?, unit_price = ?, cost_price = ?, stock_quantity = ?, is_active = ? WHERE product_id = ?',
            [product_name, category_id, unit_price, cost_price, stock_quantity, is_active, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Product not found or no changes made' });
        res.json({ message: 'Product updated successfully' });
    } catch (err) {
        console.error('Error updating product:', err);
        res.status(500).json({ message: 'Error updating product', error: err.message });
    }
});

app.delete('/api/products/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        // If the Products table had a main_user_id column:
        // const [productCheck] = await pool.query('SELECT product_id FROM Products WHERE product_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        // if (productCheck.length === 0) {
        //     return res.status(404).json({ message: 'Product not found or not authorized.' });
        // }
        const [result] = await pool.query('UPDATE Products SET is_active = FALSE WHERE product_id = ?', [id]); // Soft delete
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Product not found' });
        res.json({ message: 'Product deleted (deactivated) successfully' });
    } catch (err) {
        console.error('Error deleting product:', err);
        res.status(500).json({ message: 'Error deleting product', error: err.message });
    }
});

// Categories API
app.get('/api/categories', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT c.* FROM Categories c';
        const params = [];
        if (req.mainUserId) {
            // Categories are not directly linked to main_user_id.
            // Assuming categories are globally accessible or linked via other means.
            // If the Categories table had a main_user_id column:
            // query += ' WHERE c.main_user_id = ?';
            // params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ message: 'Error fetching categories', error: err.message });
    }
});

app.get('/api/categories/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT c.* FROM Categories c WHERE c.category_id = ?';
        const params = [id];
        if (req.mainUserId) {
            // Similar logic as above.
            // If the Categories table had a main_user_id column:
            // query += ' AND c.main_user_id = ?';
            // params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Category not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching category:', err);
        res.status(500).json({ message: 'Error fetching category', error: err.message });
    }
});

app.post('/api/categories', authenticateToken, authorizeMainUser, async (req, res) => {
    const { category_name } = req.body;
    if (!category_name) return res.status(400).json({ message: 'Category name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Categories (category_name) VALUES (?)', [category_name]);
        res.status(201).json({ message: 'Category created successfully', categoryId: result.insertId });
    } catch (err) {
        console.error('Error creating category:', err);
        res.status(500).json({ message: 'Error creating category', error: err.message });
    }
});

app.put('/api/categories/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { category_name } = req.body;
    try {
        // If the Categories table had a main_user_id column:
        // const [categoryCheck] = await pool.query('SELECT category_id FROM Categories WHERE category_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        // if (categoryCheck.length === 0) {
        //     return res.status(404).json({ message: 'Category not found or not authorized.' });
        // }
        const [result] = await pool.query('UPDATE Categories SET category_name = ? WHERE category_id = ?', [category_name, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Category not found or no changes made' });
        res.json({ message: 'Category updated successfully' });
    } catch (err) {
        console.error('Error updating category:', err);
        res.status(500).json({ message: 'Error updating category', error: err.message });
    }
});

app.delete('/api/categories/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        // If the Categories table had a main_user_id column:
        // const [categoryCheck] = await pool.query('SELECT category_id FROM Categories WHERE category_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        // if (categoryCheck.length === 0) {
        //     return res.status(404).json({ message: 'Category not found or not authorized.' });
        // }
        const [result] = await pool.query('DELETE FROM Categories WHERE category_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Category not found' });
        res.json({ message: 'Category deleted successfully' });
    } catch (err) {
        console.error('Error deleting category:', err);
        res.status(500).json({ message: 'Error deleting category', error: err.message });
    }
});


// Customers API
app.get('/api/customers', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT c.* FROM Customers c';
        const params = [];
        if (req.mainUserId) {
            query += ' JOIN SalesOrders so ON c.customer_id = so.customer_id WHERE so.main_user_id = ? GROUP BY c.customer_id';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching customers:', err);
        res.status(500).json({ message: 'Error fetching customers', error: err.message });
    }
});

app.get('/api/customers/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT c.* FROM Customers c WHERE c.customer_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND c.customer_id IN (SELECT customer_id FROM SalesOrders WHERE main_user_id = ?)';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Customer not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching customer:', err);
        res.status(500).json({ message: 'Error fetching customer', error: err.message });
    }
});

app.post('/api/customers', authenticateToken, authorizeMainUser, async (req, res) => {
    const { customer_name, phone, email, address } = req.body;
    if (!customer_name) return res.status(400).json({ message: 'Customer name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Customers (customer_name, phone, email, address) VALUES (?, ?, ?, ?)', [customer_name, phone, email, address]);
        res.status(201).json({ message: 'Customer created successfully', customerId: result.insertId });
    } catch (err) {
        console.error('Error creating customer:', err);
        res.status(500).json({ message: 'Error creating customer', error: err.message });
    }
});

app.put('/api/customers/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { customer_name, phone, email, address } = req.body;
    try {
        if (req.mainUserId) {
            const [customerCheck] = await pool.query('SELECT c.* FROM Customers c JOIN SalesOrders so ON c.customer_id = so.customer_id WHERE c.customer_id = ? AND so.main_user_id = ? GROUP BY c.customer_id', [id, req.mainUserId]);
            if (customerCheck.length === 0) {
                return res.status(404).json({ message: 'Customer not found or not authorized.' });
            }
        }
        const [result] = await pool.query('UPDATE Customers SET customer_name = ?, phone = ?, email = ?, address = ? WHERE customer_id = ?', [customer_name, phone, email, address, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Customer not found or no changes made' });
        res.json({ message: 'Customer updated successfully' });
    } catch (err) {
        console.error('Error updating customer:', err);
        res.status(500).json({ message: 'Error updating customer', error: err.message });
    }
});

app.delete('/api/customers/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        if (req.mainUserId) {
            const [customerCheck] = await pool.query('SELECT c.* FROM Customers c JOIN SalesOrders so ON c.customer_id = so.customer_id WHERE c.customer_id = ? AND so.main_user_id = ? GROUP BY c.customer_id', [id, req.mainUserId]);
            if (customerCheck.length === 0) {
                return res.status(404).json({ message: 'Customer not found or not authorized.' });
            }
        }
        const [result] = await pool.query('DELETE FROM Customers WHERE customer_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Customer not found' });
        res.json({ message: 'Customer deleted successfully' });
    } catch (err) {
        console.error('Error deleting customer:', err);
        res.status(500).json({ message: 'Error deleting customer', error: err.message });
    }
});

// SalesOrders API
app.get('/api/salesorders', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM SalesOrders';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching sales orders:', err);
        res.status(500).json({ message: 'Error fetching sales orders', error: err.message });
    }
});

app.get('/api/salesorders/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM SalesOrders WHERE order_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Sales order not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching sales order:', err);
        res.status(500).json({ message: 'Error fetching sales order', error: err.message });
    }
});

app.post('/api/salesorders', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status, items } = req.body;
    if (!user_id || !branch_id || !net_amount || !items || items.length === 0) {
        return res.status(400).json({ message: 'User ID, Branch ID, Net Amount, and at least one item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [userCheck] = await connection.query('SELECT user_id FROM Users WHERE user_id = ? AND (main_user_id = ? OR user_id = ?)', [user_id, req.mainUserId, req.mainUserId]);
        if (userCheck.length === 0) return res.status(403).json({ message: 'User not authorized for this sales order.' });

        const [branchCheck] = await connection.query('SELECT b.branch_id FROM Branches b JOIN Companies c ON b.company_id = c.company_id WHERE b.branch_id = ? AND c.main_user_id = ?', [branch_id, req.mainUserId]);
        if (branchCheck.length === 0) return res.status(403).json({ message: 'Branch not authorized for this sales order.' });

        const [orderResult] = await connection.query(
            'INSERT INTO SalesOrders (customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status, main_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status, req.mainUserId]
        );
        const orderId = orderResult.insertId;

        for (const item of items) {
            // Product check is removed here to allow any product to be sold,
            // assuming product existence is handled by frontend or a separate product management.
            // If main_user_id needs to be linked to products, add it to Products table.

            await connection.query(
                'INSERT INTO SalesOrderItems (order_id, product_id, quantity, unit_price, subtotal) VALUES (?, ?, ?, ?, ?)',
                [orderId, item.product_id, item.quantity, item.unit_price, item.subtotal]
            );
            await connection.query(
                'INSERT INTO InventoryTransactions (product_id, warehouse_id, transaction_type, quantity_change, reference_doc_type, reference_doc_id, user_id, description, main_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [item.product_id, branch_id, 'Sale', -item.quantity, 'SalesOrder', orderId, user_id, `Sale for Order ${orderId}`, req.mainUserId]
            );
        }

        await connection.commit();
        res.status(201).json({ message: 'Sales order created successfully', orderId: orderId });
    } catch (err) {
        if (connection) await connection.rollback();
        console.error('Error creating sales order:', err);
        res.status(500).json({ message: 'Error creating sales order', error: err.message });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/salesorders/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE SalesOrders SET customer_id = ?, user_id = ?, branch_id = ?, total_amount = ?, discount_amount = ?, tax_amount = ?, net_amount = ?, status = ? WHERE order_id = ? AND main_user_id = ?',
            [customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status, id, req.mainUserId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Sales order not found, not authorized, or no changes made' });
        res.json({ message: 'Sales order updated successfully' });
    } catch (err) {
        console.error('Error updating sales order:', err);
        res.status(500).json({ message: 'Error updating sales order', error: err.message });
    }
});

app.delete('/api/salesorders/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE SalesOrders SET status = "Canceled" WHERE order_id = ? AND main_user_id = ?', [id, req.mainUserId]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Sales order not found or not authorized' });
        res.json({ message: 'Sales order cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling sales order:', err);
        res.status(500).json({ message: 'Error cancelling sales order', error: err.message });
    }
});

// SalesOrderItems API
app.get('/api/salesorderitems', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT soi.* FROM SalesOrderItems soi JOIN SalesOrders so ON soi.order_id = so.order_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE so.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching sales order items:', err);
        res.status(500).json({ message: 'Error fetching sales order items', error: err.message });
    }
});

app.get('/api/salesorderitems/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT soi.* FROM SalesOrderItems soi JOIN SalesOrders so ON soi.order_id = so.order_id WHERE soi.order_item_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND so.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Sales order item not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching sales order item:', err);
        res.status(500).json({ message: 'Error fetching sales order item', error: err.message });
    }
});

// Payments API
app.get('/api/payments', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT p.* FROM Payments p JOIN SalesOrders so ON p.order_id = so.order_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE so.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payments:', err);
        res.status(500).json({ message: 'Error fetching payments', error: err.message });
    }
});

app.get('/api/payments/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT p.* FROM Payments p JOIN SalesOrders so ON p.order_id = so.order_id WHERE p.payment_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND so.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Payment not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payment:', err);
        res.status(500).json({ message: 'Error fetching payment', error: err.message });
    }
});

app.post('/api/payments', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { order_id, payment_method, amount_paid, transaction_ref } = req.body;
    if (!order_id || !payment_method || !amount_paid) return res.status(400).json({ message: 'Order ID, payment method, and amount paid are required.' });
    try {
        const [orderCheck] = await pool.query('SELECT order_id FROM SalesOrders WHERE order_id = ? AND main_user_id = ?', [order_id, req.mainUserId]);
        if (orderCheck.length === 0) return res.status(403).json({ message: 'Sales order not found or not authorized for this payment.' });

        const [result] = await pool.query('INSERT INTO Payments (order_id, payment_method, amount_paid, transaction_ref) VALUES (?, ?, ?, ?)', [order_id, payment_method, amount_paid, transaction_ref]);
        res.status(201).json({ message: 'Payment recorded successfully', paymentId: result.insertId });
    } catch (err) {
        console.error('Error recording payment:', err);
        res.status(500).json({ message: 'Error recording payment', error: err.message });
    }
});

app.put('/api/payments/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { order_id, payment_method, amount_paid, payment_date, transaction_ref } = req.body;
    try {
        const [paymentCheck] = await pool.query('SELECT p.payment_id FROM Payments p JOIN SalesOrders so ON p.order_id = so.order_id WHERE p.payment_id = ? AND so.main_user_id = ?', [id, req.mainUserId]);
        if (paymentCheck.length === 0) return res.status(404).json({ message: 'Payment not found or not authorized.' });

        const [result] = await pool.query('UPDATE Payments SET order_id = ?, payment_method = ?, amount_paid = ?, payment_date = ?, transaction_ref = ? WHERE payment_id = ?', [order_id, payment_method, amount_paid, payment_date, transaction_ref, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment not found or no changes made' });
        res.json({ message: 'Payment updated successfully' });
    } catch (err) {
        console.error('Error updating payment:', err);
        res.status(500).json({ message: 'Error updating payment', error: err.message });
    }
});

app.delete('/api/payments/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [paymentCheck] = await pool.query('SELECT p.payment_id FROM Payments p JOIN SalesOrders so ON p.order_id = so.order_id WHERE p.payment_id = ? AND so.main_user_id = ?', [id, req.mainUserId]);
        if (paymentCheck.length === 0) return res.status(404).json({ message: 'Payment not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM Payments WHERE payment_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment not found' });
        res.json({ message: 'Payment deleted successfully' });
    } catch (err) {
        console.error('Error deleting payment:', err);
        res.status(500).json({ message: 'Error deleting payment', error: err.message });
    }
});

// DailyCashRegister API
app.get('/api/dailycashregisters', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM DailyCashRegister';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching daily cash registers:', err);
        res.status(500).json({ message: 'Error fetching daily cash registers', error: err.message });
    }
});

app.get('/api/dailycashregisters/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM DailyCashRegister WHERE register_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Daily cash register not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching daily cash register:', err);
        res.status(500).json({ message: 'Error fetching daily cash register', error: err.message });
    }
});

app.post('/api/dailycashregisters', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { user_id, branch_id, open_time, starting_cash } = req.body;
    if (!user_id || !branch_id || !open_time || starting_cash === undefined) {
        return res.status(400).json({ message: 'User ID, Branch ID, open time, and starting cash are required.' });
    }
    try {
        const [userCheck] = await pool.query('SELECT user_id FROM Users WHERE user_id = ? AND (main_user_id = ? OR user_id = ?)', [user_id, req.mainUserId, req.mainUserId]);
        if (userCheck.length === 0) return res.status(403).json({ message: 'User not authorized for this cash register.' });

        const [branchCheck] = await pool.query('SELECT b.branch_id FROM Branches b JOIN Companies c ON b.company_id = c.company_id WHERE b.branch_id = ? AND c.main_user_id = ?', [branch_id, req.mainUserId]);
        if (branchCheck.length === 0) return res.status(403).json({ message: 'Branch not authorized for this cash register.' });

        const [result] = await pool.query(
            'INSERT INTO DailyCashRegister (user_id, branch_id, open_time, starting_cash, main_user_id) VALUES (?, ?, ?, ?, ?)',
            [user_id, branch_id, open_time, starting_cash, req.mainUserId]
        );
        res.status(201).json({ message: 'Daily cash register created successfully', registerId: result.insertId });
    } catch (err) {
        console.error('Error creating daily cash register:', err);
        res.status(500).json({ message: 'Error creating daily cash register', error: err.message });
    }
});

app.put('/api/dailycashregisters/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { close_time, ending_cash, total_sales_cash, total_sales_credit, discrepancy } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE DailyCashRegister SET close_time = ?, ending_cash = ?, total_sales_cash = ?, total_sales_credit = ?, discrepancy = ? WHERE register_id = ? AND main_user_id = ?',
            [close_time, ending_cash, total_sales_cash, total_sales_credit, discrepancy, id, req.mainUserId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Daily cash register not found, not authorized, or no changes made' });
        res.json({ message: 'Daily cash register updated successfully' });
    } catch (err) {
        console.error('Error updating daily cash register:', err);
        res.status(500).json({ message: 'Error updating daily cash register', error: err.message });
    }
});

app.delete('/api/dailycashregisters/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM DailyCashRegister WHERE register_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Daily cash register not found or not authorized' });
        res.json({ message: 'Daily cash register deleted successfully' });
    } catch (err) {
        console.error('Error deleting daily cash register:', err);
        res.status(500).json({ message: 'Error deleting daily cash register', error: err.message });
    }
});


// --- HR Module Tables ---

// Attendance API
app.get('/api/attendance', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT a.* FROM Attendance a JOIN Employees e ON a.employee_id = e.employee_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching attendance records:', err);
        res.status(500).json({ message: 'Error fetching attendance records', error: err.message });
    }
});

app.get('/api/attendance/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT a.* FROM Attendance a JOIN Employees e ON a.employee_id = e.employee_id WHERE a.attendance_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Attendance record not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching attendance record:', err);
        res.status(500).json({ message: 'Error fetching attendance record', error: err.message });
    }
});

app.post('/api/attendance', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { employee_id, check_in_time, check_out_time, status } = req.body;
    if (!employee_id || !check_in_time) return res.status(400).json({ message: 'Employee ID and check-in time are required.' });
    try {
        const [employeeCheck] = await pool.query('SELECT employee_id FROM Employees WHERE employee_id = ? AND main_user_id = ?', [employee_id, req.mainUserId]);
        if (employeeCheck.length === 0) return res.status(403).json({ message: 'Employee not found or not authorized for this attendance record.' });

        const [result] = await pool.query('INSERT INTO Attendance (employee_id, check_in_time, check_out_time, status) VALUES (?, ?, ?, ?)', [employee_id, check_in_time, check_out_time, status]);
        res.status(201).json({ message: 'Attendance record created successfully', attendanceId: result.insertId });
    } catch (err) {
        console.error('Error creating attendance record:', err);
        res.status(500).json({ message: 'Error creating attendance record', error: err.message });
    }
});

app.put('/api/attendance/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { employee_id, check_in_time, check_out_time, status } = req.body;
    try {
        const [attendanceCheck] = await pool.query('SELECT a.attendance_id FROM Attendance a JOIN Employees e ON a.employee_id = e.employee_id WHERE a.attendance_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (attendanceCheck.length === 0) return res.status(404).json({ message: 'Attendance record not found or not authorized.' });

        const [result] = await pool.query('UPDATE Attendance SET employee_id = ?, check_in_time = ?, check_out_time = ?, status = ? WHERE attendance_id = ?', [employee_id, check_in_time, check_out_time, status, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Attendance record not found or no changes made' });
        res.json({ message: 'Attendance record updated successfully' });
    } catch (err) {
        console.error('Error updating attendance record:', err);
        res.status(500).json({ message: 'Error updating attendance record', error: err.message });
    }
});

app.delete('/api/attendance/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [attendanceCheck] = await pool.query('SELECT a.attendance_id FROM Attendance a JOIN Employees e ON a.employee_id = e.employee_id WHERE a.attendance_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (attendanceCheck.length === 0) return res.status(404).json({ message: 'Attendance record not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM Attendance WHERE attendance_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Attendance record not found' });
        res.json({ message: 'Attendance record deleted successfully' });
    } catch (err) {
        console.error('Error deleting attendance record:', err);
        res.status(500).json({ message: 'Error deleting attendance record', error: err.message });
    }
});

// LeaveTypes API
app.get('/api/leavetypes', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT lt.* FROM LeaveTypes lt';
        const params = [];
        if (req.mainUserId) {
            query += ' JOIN LeaveRequests lr ON lt.leave_type_id = lr.leave_type_id JOIN Employees e ON lr.employee_id = e.employee_id WHERE e.main_user_id = ? GROUP BY lt.leave_type_id';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching leave types:', err);
        res.status(500).json({ message: 'Error fetching leave types', error: err.message });
    }
});

app.get('/api/leavetypes/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT lt.* FROM LeaveTypes lt WHERE lt.leave_type_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND lt.leave_type_id IN (SELECT leave_type_id FROM LeaveRequests lr JOIN Employees e ON lr.employee_id = e.employee_id WHERE e.main_user_id = ?)';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Leave type not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching leave type:', err);
        res.status(500).json({ message: 'Error fetching leave type', error: err.message });
    }
});

app.post('/api/leavetypes', authenticateToken, authorizeMainUser, async (req, res) => {
    const { type_name, description } = req.body;
    if (!type_name) return res.status(400).json({ message: 'Leave type name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO LeaveTypes (type_name, description) VALUES (?, ?)', [type_name, description]);
        res.status(201).json({ message: 'Leave type created successfully', leaveTypeId: result.insertId });
    } catch (err) {
        console.error('Error creating leave type:', err);
        res.status(500).json({ message: 'Error creating leave type', error: err.message });
    }
});

app.put('/api/leavetypes/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { type_name, description } = req.body;
    try {
        if (req.mainUserId) {
            const [leaveTypeCheck] = await pool.query('SELECT lt.* FROM LeaveTypes lt JOIN LeaveRequests lr ON lt.leave_type_id = lr.leave_type_id JOIN Employees e ON lr.employee_id = e.employee_id WHERE lt.leave_type_id = ? AND e.main_user_id = ? GROUP BY lt.leave_type_id', [id, req.mainUserId]);
            if (leaveTypeCheck.length === 0) {
                return res.status(404).json({ message: 'Leave type not found or not authorized.' });
            }
        }
        const [result] = await pool.query('UPDATE LeaveTypes SET type_name = ?, description = ? WHERE leave_type_id = ?', [type_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Leave type not found or no changes made' });
        res.json({ message: 'Leave type updated successfully' });
    } catch (err) {
        console.error('Error updating leave type:', err);
        res.status(500).json({ message: 'Error updating leave type', error: err.message });
    }
});

app.delete('/api/leavetypes/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        if (req.mainUserId) {
            const [leaveTypeCheck] = await pool.query('SELECT lt.* FROM LeaveTypes lt JOIN LeaveRequests lr ON lt.leave_type_id = lr.leave_type_id JOIN Employees e ON lr.employee_id = e.employee_id WHERE lt.leave_type_id = ? AND e.main_user_id = ? GROUP BY lt.leave_type_id', [id, req.mainUserId]);
            if (leaveTypeCheck.length === 0) {
                return res.status(404).json({ message: 'Leave type not found or not authorized.' });
            }
        }
        const [result] = await pool.query('DELETE FROM LeaveTypes WHERE leave_type_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Leave type not found' });
        res.json({ message: 'Leave type deleted successfully' });
    } catch (err) {
        console.error('Error deleting leave type:', err);
        res.status(500).json({ message: 'Error deleting leave type', error: err.message });
    }
});

// LeaveRequests API
app.get('/api/leaverequests', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT lr.* FROM LeaveRequests lr JOIN Employees e ON lr.employee_id = e.employee_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching leave requests:', err);
        res.status(500).json({ message: 'Error fetching leave requests', error: err.message });
    }
});

app.get('/api/leaverequests/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT lr.* FROM LeaveRequests lr JOIN Employees e ON lr.employee_id = e.employee_id WHERE lr.leave_request_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Leave request not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching leave request:', err);
        res.status(500).json({ message: 'Error fetching leave request', error: err.message });
    }
});

app.post('/api/leaverequests', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { employee_id, leave_type_id, start_date, end_date, number_of_days, reason, status, approved_by_user_id } = req.body;
    if (!employee_id || !leave_type_id || !start_date || !end_date || !number_of_days) {
        return res.status(400).json({ message: 'Employee ID, leave type, start/end dates, and number of days are required.' });
    }
    try {
        const [employeeCheck] = await pool.query('SELECT employee_id FROM Employees WHERE employee_id = ? AND main_user_id = ?', [employee_id, req.mainUserId]);
        if (employeeCheck.length === 0) return res.status(403).json({ message: 'Employee not found or not authorized for this leave request.' });

        const [result] = await pool.query(
            'INSERT INTO LeaveRequests (employee_id, leave_type_id, start_date, end_date, number_of_days, reason, status, approved_by_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [employee_id, leave_type_id, start_date, end_date, number_of_days, reason, status, approved_by_user_id]
        );
        res.status(201).json({ message: 'Leave request created successfully', leaveRequestId: result.insertId });
    } catch (err) {
        console.error('Error creating leave request:', err);
        res.status(500).json({ message: 'Error creating leave request', error: err.message });
    }
});

app.put('/api/leaverequests/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { employee_id, leave_type_id, start_date, end_date, number_of_days, reason, status, approved_by_user_id, approval_date } = req.body;
    try {
        const [leaveRequestCheck] = await pool.query('SELECT lr.* FROM LeaveRequests lr JOIN Employees e ON lr.employee_id = e.employee_id WHERE lr.leave_request_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (leaveRequestCheck.length === 0) return res.status(404).json({ message: 'Leave request not found or not authorized.' });

        const [result] = await pool.query(
            'UPDATE LeaveRequests SET employee_id = ?, leave_type_id = ?, start_date = ?, end_date = ?, number_of_days = ?, reason = ?, status = ?, approved_by_user_id = ?, approval_date = ? WHERE leave_request_id = ?',
            [employee_id, leave_type_id, start_date, end_date, number_of_days, reason, status, approved_by_user_id, approval_date, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Leave request not found or no changes made' });
        res.json({ message: 'Leave request updated successfully' });
    } catch (err) {
        console.error('Error updating leave request:', err);
        res.status(500).json({ message: 'Error updating leave request', error: err.message });
    }
});

app.delete('/api/leaverequests/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [leaveRequestCheck] = await pool.query('SELECT lr.* FROM LeaveRequests lr JOIN Employees e ON lr.employee_id = e.employee_id WHERE lr.leave_request_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (leaveRequestCheck.length === 0) return res.status(404).json({ message: 'Leave request not found or not authorized.' });

        const [result] = await pool.query('UPDATE LeaveRequests SET status = "Canceled" WHERE leave_request_id = ?', [id]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Leave request not found' });
        res.json({ message: 'Leave request cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling leave request:', err);
        res.status(500).json({ message: 'Error cancelling leave request', error: err.message });
    }
});

// Payrolls API
app.get('/api/payrolls', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT p.* FROM Payrolls p JOIN Employees e ON p.employee_id = e.employee_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payrolls:', err);
        res.status(500).json({ message: 'Error fetching payrolls', error: err.message });
    }
});

app.get('/api/payrolls/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT p.* FROM Payrolls p JOIN Employees e ON p.employee_id = e.employee_id WHERE p.payroll_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Payroll not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payroll:', err);
        res.status(500).json({ message: 'Error fetching payroll', error: err.message });
    }
});

app.post('/api/payrolls', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { employee_id, payroll_period_start, payroll_period_end, gross_salary, deductions, net_salary, payment_date } = req.body;
    if (!employee_id || !payroll_period_start || !payroll_period_end || !gross_salary || !net_salary || !payment_date) {
        return res.status(400).json({ message: 'Employee ID, payroll period, gross/net salary, and payment date are required.' });
    }
    try {
        const [employeeCheck] = await pool.query('SELECT employee_id FROM Employees WHERE employee_id = ? AND main_user_id = ?', [employee_id, req.mainUserId]);
        if (employeeCheck.length === 0) return res.status(403).json({ message: 'Employee not found or not authorized for this payroll.' });

        const [result] = await pool.query(
            'INSERT INTO Payrolls (employee_id, payroll_period_start, payroll_period_end, gross_salary, deductions, net_salary, payment_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [employee_id, payroll_period_start, payroll_period_end, gross_salary, JSON.stringify(deductions), net_salary, payment_date]
        );
        res.status(201).json({ message: 'Payroll created successfully', payrollId: result.insertId });
    } catch (err) {
        console.error('Error creating payroll:', err);
        res.status(500).json({ message: 'Error creating payroll', error: err.message });
    }
});

app.put('/api/payrolls/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { employee_id, payroll_period_start, payroll_period_end, gross_salary, deductions, net_salary, payment_date } = req.body;
    try {
        const [payrollCheck] = await pool.query('SELECT p.payroll_id FROM Payrolls p JOIN Employees e ON p.employee_id = e.employee_id WHERE p.payroll_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (payrollCheck.length === 0) return res.status(404).json({ message: 'Payroll not found or not authorized.' });

        const [result] = await pool.query(
            'UPDATE Payrolls SET employee_id = ?, payroll_period_start = ?, payroll_period_end = ?, gross_salary = ?, deductions = ?, net_salary = ?, payment_date = ? WHERE payroll_id = ?',
            [employee_id, payroll_period_start, payroll_period_end, gross_salary, JSON.stringify(deductions), net_salary, payment_date, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payroll not found or no changes made' });
        res.json({ message: 'Payroll updated successfully' });
    } catch (err) {
        console.error('Error updating payroll:', err);
        res.status(500).json({ message: 'Error updating payroll', error: err.message });
    }
});

app.delete('/api/payrolls/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [payrollCheck] = await pool.query('SELECT p.payroll_id FROM Payrolls p JOIN Employees e ON p.employee_id = e.employee_id WHERE p.payroll_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (payrollCheck.length === 0) return res.status(404).json({ message: 'Payroll not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM Payrolls WHERE payroll_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payroll not found' });
        res.json({ message: 'Payroll deleted successfully' });
    } catch (err) {
        console.error('Error deleting payroll:', err);
        res.status(500).json({ message: 'Error deleting payroll', error: err.message });
    }
});

// Benefits API
app.get('/api/benefits', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT b.* FROM Benefits b';
        const params = [];
        if (req.mainUserId) {
            query += ' JOIN EmployeeBenefits eb ON b.benefit_id = eb.benefit_id JOIN Employees e ON eb.employee_id = e.employee_id WHERE e.main_user_id = ? GROUP BY b.benefit_id';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching benefits:', err);
        res.status(500).json({ message: 'Error fetching benefits', error: err.message });
    }
});

app.get('/api/benefits/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT b.* FROM Benefits b WHERE b.benefit_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND b.benefit_id IN (SELECT benefit_id FROM EmployeeBenefits eb JOIN Employees e ON eb.employee_id = e.employee_id WHERE e.main_user_id = ?)';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Benefit not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching benefit:', err);
        res.status(500).json({ message: 'Error fetching benefit', error: err.message });
    }
});

app.post('/api/benefits', authenticateToken, authorizeMainUser, async (req, res) => {
    const { benefit_name, description } = req.body;
    if (!benefit_name) return res.status(400).json({ message: 'Benefit name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Benefits (benefit_name, description) VALUES (?, ?)', [benefit_name, description]);
        res.status(201).json({ message: 'Benefit created successfully', benefitId: result.insertId });
    } catch (err) {
        console.error('Error creating benefit:', err);
        res.status(500).json({ message: 'Error creating benefit', error: err.message });
    }
});

app.put('/api/benefits/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { benefit_name, description } = req.body;
    try {
        if (req.mainUserId) {
            const [benefitCheck] = await pool.query('SELECT b.* FROM Benefits b JOIN EmployeeBenefits eb ON b.benefit_id = eb.benefit_id JOIN Employees e ON eb.employee_id = e.employee_id WHERE b.benefit_id = ? AND e.main_user_id = ? GROUP BY b.benefit_id', [id, req.mainUserId]);
            if (benefitCheck.length === 0) {
                return res.status(404).json({ message: 'Benefit not found or not authorized.' });
            }
        }
        const [result] = await pool.query('UPDATE Benefits SET benefit_name = ?, description = ? WHERE benefit_id = ?', [benefit_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Benefit not found or no changes made' });
        res.json({ message: 'Benefit updated successfully' });
    } catch (err) {
        console.error('Error updating benefit:', err);
        res.status(500).json({ message: 'Error updating benefit', error: err.message });
    }
});

app.delete('/api/benefits/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        if (req.mainUserId) {
            const [benefitCheck] = await pool.query('SELECT b.* FROM Benefits b JOIN EmployeeBenefits eb ON b.benefit_id = eb.benefit_id JOIN Employees e ON eb.employee_id = e.employee_id WHERE b.benefit_id = ? AND e.main_user_id = ? GROUP BY b.benefit_id', [id, req.mainUserId]);
            if (benefitCheck.length === 0) {
                return res.status(404).json({ message: 'Benefit not found or not authorized.' });
            }
        }
        const [result] = await pool.query('DELETE FROM Benefits WHERE benefit_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Benefit not found' });
        res.json({ message: 'Benefit deleted successfully' });
    } catch (err) {
        console.error('Error deleting benefit:', err);
        res.status(500).json({ message: 'Error deleting benefit', error: err.message });
    }
});

// EmployeeBenefits API
app.get('/api/employeebenefits', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT eb.* FROM EmployeeBenefits eb JOIN Employees e ON eb.employee_id = e.employee_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching employee benefits:', err);
        res.status(500).json({ message: 'Error fetching employee benefits', error: err.message });
    }
});

app.get('/api/employeebenefits/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT eb.* FROM EmployeeBenefits eb JOIN Employees e ON eb.employee_id = e.employee_id WHERE eb.employee_benefit_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Employee benefit not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching employee benefit:', err);
        res.status(500).json({ message: 'Error fetching employee benefit', error: err.message });
    }
});

app.post('/api/employeebenefits', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { employee_id, benefit_id, effective_date, end_date } = req.body;
    if (!employee_id || !benefit_id || !effective_date) return res.status(400).json({ message: 'Employee ID, benefit ID, and effective date are required.' });
    try {
        const [employeeCheck] = await pool.query('SELECT employee_id FROM Employees WHERE employee_id = ? AND main_user_id = ?', [employee_id, req.mainUserId]);
        if (employeeCheck.length === 0) return res.status(403).json({ message: 'Employee not found or not authorized for this employee benefit.' });

        const [result] = await pool.query('INSERT INTO EmployeeBenefits (employee_id, benefit_id, effective_date, end_date) VALUES (?, ?, ?, ?)', [employee_id, benefit_id, effective_date, end_date]);
        res.status(201).json({ message: 'Employee benefit assigned successfully', employeeBenefitId: result.insertId });
    } catch (err) {
        console.error('Error assigning employee benefit:', err);
        res.status(500).json({ message: 'Error assigning employee benefit', error: err.message });
    }
});

app.put('/api/employeebenefits/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { employee_id, benefit_id, effective_date, end_date } = req.body;
    try {
        const [employeeBenefitCheck] = await pool.query('SELECT eb.* FROM EmployeeBenefits eb JOIN Employees e ON eb.employee_id = e.employee_id WHERE eb.employee_benefit_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (employeeBenefitCheck.length === 0) return res.status(404).json({ message: 'Employee benefit not found or not authorized.' });

        const [result] = await pool.query('UPDATE EmployeeBenefits SET employee_id = ?, benefit_id = ?, effective_date = ?, end_date = ? WHERE employee_benefit_id = ?', [employee_id, benefit_id, effective_date, end_date, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee benefit not found or no changes made' });
        res.json({ message: 'Employee benefit updated successfully' });
    } catch (err) {
        console.error('Error updating employee benefit:', err);
        res.status(500).json({ message: 'Error updating employee benefit', error: err.message });
    }
});

app.delete('/api/employeebenefits/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [employeeBenefitCheck] = await pool.query('SELECT eb.* FROM EmployeeBenefits eb JOIN Employees e ON eb.employee_id = e.employee_id WHERE eb.employee_benefit_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (employeeBenefitCheck.length === 0) return res.status(404).json({ message: 'Employee benefit not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM EmployeeBenefits WHERE employee_benefit_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee benefit not found' });
        res.json({ message: 'Employee benefit deleted successfully' });
    } catch (err) {
        console.error('Error deleting employee benefit:', err);
        res.status(500).json({ message: 'Error deleting employee benefit', error: err.message });
    }
});

// PerformanceReviews API
app.get('/api/performancereviews', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT pr.* FROM PerformanceReviews pr JOIN Employees e ON pr.employee_id = e.employee_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching performance reviews:', err);
        res.status(500).json({ message: 'Error fetching performance reviews', error: err.message });
    }
});

app.get('/api/performancereviews/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT pr.* FROM PerformanceReviews pr JOIN Employees e ON pr.employee_id = e.employee_id WHERE pr.review_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND e.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Performance review not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching performance review:', err);
        res.status(500).json({ message: 'Error fetching performance review', error: err.message });
    }
});

app.post('/api/performancereviews', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { employee_id, reviewer_id, review_date, rating, comments } = req.body;
    if (!employee_id || !reviewer_id || !review_date) return res.status(400).json({ message: 'Employee ID, reviewer ID, and review date are required.' });
    try {
        const [employeeCheck] = await pool.query('SELECT employee_id FROM Employees WHERE employee_id = ? AND main_user_id = ?', [employee_id, req.mainUserId]);
        const [reviewerCheck] = await pool.query('SELECT employee_id FROM Employees WHERE employee_id = ? AND main_user_id = ?', [reviewer_id, req.mainUserId]);
        if (employeeCheck.length === 0 || reviewerCheck.length === 0) return res.status(403).json({ message: 'Employee or reviewer not found or not authorized for this performance review.' });

        const [result] = await pool.query('INSERT INTO PerformanceReviews (employee_id, reviewer_id, review_date, rating, comments) VALUES (?, ?, ?, ?, ?)', [employee_id, reviewer_id, review_date, rating, comments]);
        res.status(201).json({ message: 'Performance review created successfully', reviewId: result.insertId });
    } catch (err) {
        console.error('Error creating performance review:', err);
        res.status(500).json({ message: 'Error creating performance review', error: err.message });
    }
});

app.put('/api/performancereviews/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { employee_id, reviewer_id, review_date, rating, comments } = req.body;
    try {
        const [performanceReviewCheck] = await pool.query('SELECT pr.* FROM PerformanceReviews pr JOIN Employees e ON pr.employee_id = e.employee_id WHERE pr.review_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (performanceReviewCheck.length === 0) return res.status(404).json({ message: 'Performance review not found or not authorized.' });

        const [result] = await pool.query('UPDATE PerformanceReviews SET employee_id = ?, reviewer_id = ?, review_date = ?, rating = ?, comments = ? WHERE review_id = ?', [employee_id, reviewer_id, review_date, rating, comments, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Performance review not found or no changes made' });
        res.json({ message: 'Performance review updated successfully' });
    } catch (err) {
        console.error('Error updating performance review:', err);
        res.status(500).json({ message: 'Error updating performance review', error: err.message });
    }
});

app.delete('/api/performancereviews/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [performanceReviewCheck] = await pool.query('SELECT pr.* FROM PerformanceReviews pr JOIN Employees e ON pr.employee_id = e.employee_id WHERE pr.review_id = ? AND e.main_user_id = ?', [id, req.mainUserId]);
        if (performanceReviewCheck.length === 0) return res.status(404).json({ message: 'Performance review not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM PerformanceReviews WHERE review_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Performance review not found' });
        res.json({ message: 'Performance review deleted successfully' });
    } catch (err) {
        console.error('Error deleting performance review:', err);
        res.status(500).json({ message: 'Error deleting performance review', error: err.message });
    }
});


// --- ERP Module Tables (Inventory & Purchasing) ---

// Suppliers API
app.get('/api/suppliers', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT s.* FROM Suppliers s';
        const params = [];
        if (req.mainUserId) {
            query += ' JOIN PurchaseOrders po ON s.supplier_id = po.supplier_id WHERE po.main_user_id = ? GROUP BY s.supplier_id';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching suppliers:', err);
        res.status(500).json({ message: 'Error fetching suppliers', error: err.message });
    }
});

app.get('/api/suppliers/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT s.* FROM Suppliers s WHERE s.supplier_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND s.supplier_id IN (SELECT supplier_id FROM PurchaseOrders WHERE main_user_id = ?)';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Supplier not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching supplier:', err);
        res.status(500).json({ message: 'Error fetching supplier', error: err.message });
    }
});

app.post('/api/suppliers', authenticateToken, authorizeMainUser, async (req, res) => {
    const { supplier_name, contact_person, phone, email, address } = req.body;
    if (!supplier_name) return res.status(400).json({ message: 'Supplier name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Suppliers (supplier_name, contact_person, phone, email, address) VALUES (?, ?, ?, ?, ?)', [supplier_name, contact_person, phone, email, address]);
        res.status(201).json({ message: 'Supplier created successfully', supplierId: result.insertId });
    } catch (err) {
        console.error('Error creating supplier:', err);
        res.status(500).json({ message: 'Error creating supplier', error: err.message });
    }
});

app.put('/api/suppliers/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { supplier_name, contact_person, phone, email, address } = req.body;
    try {
        if (req.mainUserId) {
            const [supplierCheck] = await pool.query('SELECT s.* FROM Suppliers s JOIN PurchaseOrders po ON s.supplier_id = po.supplier_id WHERE s.supplier_id = ? AND po.main_user_id = ? GROUP BY s.supplier_id', [id, req.mainUserId]);
            if (supplierCheck.length === 0) {
                return res.status(404).json({ message: 'Supplier not found or not authorized.' });
            }
        }
        const [result] = await pool.query('UPDATE Suppliers SET supplier_name = ?, contact_person = ?, phone = ?, email = ?, address = ? WHERE supplier_id = ?', [supplier_name, contact_person, phone, email, address, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Supplier not found or no changes made' });
        res.json({ message: 'Supplier updated successfully' });
    } catch (err) {
        console.error('Error updating supplier:', err);
        res.status(500).json({ message: 'Error updating supplier', error: err.message });
    }
});

app.delete('/api/suppliers/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        if (req.mainUserId) {
            const [supplierCheck] = await pool.query('SELECT s.* FROM Suppliers s JOIN PurchaseOrders po ON s.supplier_id = po.supplier_id WHERE s.supplier_id = ? AND po.main_user_id = ? GROUP BY s.supplier_id', [id, req.mainUserId]);
            if (supplierCheck.length === 0) {
                return res.status(404).json({ message: 'Supplier not found or not authorized.' });
            }
        }
        const [result] = await pool.query('DELETE FROM Suppliers WHERE supplier_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Supplier not found' });
        res.json({ message: 'Supplier deleted successfully' });
    } catch (err) {
        console.error('Error deleting supplier:', err);
        res.status(500).json({ message: 'Error deleting supplier', error: err.message });
    }
});

// Warehouses API
app.get('/api/warehouses', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT w.* FROM Warehouses w JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE c.main_user_id = ?';
            params.push(req.mainUserId);
        }
        query += ' GROUP BY w.warehouse_id';
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching warehouses:', err);
        res.status(500).json({ message: 'Error fetching warehouses', error: err.message });
    }
});

app.get('/api/warehouses/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT w.* FROM Warehouses w JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE w.warehouse_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND c.main_user_id = ?';
            params.push(req.mainUserId);
        }
        query += ' GROUP BY w.warehouse_id';
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Warehouse not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching warehouse:', err);
        res.status(500).json({ message: 'Error fetching warehouse', error: err.message });
    }
});

app.post('/api/warehouses', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { warehouse_name, address, branch_id } = req.body;
    if (!warehouse_name) return res.status(400).json({ message: 'Warehouse name is required.' });
    try {
        const [branchCheck] = await pool.query('SELECT b.branch_id FROM Branches b JOIN Companies c ON b.company_id = c.company_id WHERE b.branch_id = ? AND c.main_user_id = ?', [branch_id, req.mainUserId]);
        if (branchCheck.length === 0) return res.status(403).json({ message: 'Branch not found or not authorized for this warehouse.' });

        const [result] = await pool.query('INSERT INTO Warehouses (warehouse_name, address, branch_id) VALUES (?, ?, ?)', [warehouse_name, address, branch_id]);
        res.status(201).json({ message: 'Warehouse created successfully', warehouseId: result.insertId });
    } catch (err) {
        console.error('Error creating warehouse:', err);
        res.status(500).json({ message: 'Error creating warehouse', error: err.message });
    }
});

app.put('/api/warehouses/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { warehouse_name, address, branch_id } = req.body;
    try {
        const [warehouseCheck] = await pool.query('SELECT w.* FROM Warehouses w JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE w.warehouse_id = ? AND c.main_user_id = ? GROUP BY w.warehouse_id', [id, req.mainUserId]);
        if (warehouseCheck.length === 0) return res.status(404).json({ message: 'Warehouse not found or not authorized.' });

        const [result] = await pool.query('UPDATE Warehouses SET warehouse_name = ?, address = ?, branch_id = ? WHERE warehouse_id = ?', [warehouse_name, address, branch_id, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Warehouse not found or no changes made' });
        res.json({ message: 'Warehouse updated successfully' });
    } catch (err) {
        console.error('Error updating warehouse:', err);
        res.status(500).json({ message: 'Error updating warehouse', error: err.message });
    }
});

app.delete('/api/warehouses/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [warehouseCheck] = await pool.query('SELECT w.* FROM Warehouses w JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE w.warehouse_id = ? AND c.main_user_id = ? GROUP BY w.warehouse_id', [id, req.mainUserId]);
        if (warehouseCheck.length === 0) return res.status(404).json({ message: 'Warehouse not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM Warehouses WHERE warehouse_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Warehouse not found' });
        res.json({ message: 'Warehouse deleted successfully' });
    } catch (err) {
        console.error('Error deleting warehouse:', err);
        res.status(500).json({ message: 'Error deleting warehouse', error: err.message });
    }
});

// InventoryLevels API
app.get('/api/inventorylevels', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT il.* FROM InventoryLevels il JOIN Warehouses w ON il.warehouse_id = w.warehouse_id JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE c.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching inventory levels:', err);
        res.status(500).json({ message: 'Error fetching inventory levels', error: err.message });
    }
});

app.get('/api/inventorylevels/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT il.* FROM InventoryLevels il JOIN Warehouses w ON il.warehouse_id = w.warehouse_id JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE il.inventory_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND c.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Inventory level not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching inventory level:', err);
        res.status(500).json({ message: 'Error fetching inventory level', error: err.message });
    }
});

app.post('/api/inventorylevels', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point } = req.body;
    if (!product_id || !warehouse_id || quantity_on_hand === undefined) return res.status(400).json({ message: 'Product ID, warehouse ID, and quantity on hand are required.' });
    try {
        const [warehouseCheck] = await pool.query('SELECT w.* FROM Warehouses w JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE w.warehouse_id = ? AND c.main_user_id = ?', [warehouse_id, req.mainUserId]);
        if (warehouseCheck.length === 0) return res.status(403).json({ message: 'Warehouse not found or not authorized for this inventory level.' });

        const [result] = await pool.query('INSERT INTO InventoryLevels (product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point) VALUES (?, ?, ?, ?, ?)', [product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point]);
        res.status(201).json({ message: 'Inventory level created successfully', inventoryId: result.insertId });
    } catch (err) {
        console.error('Error creating inventory level:', err);
        res.status(500).json({ message: 'Error creating inventory level', error: err.message });
    }
});

app.put('/api/inventorylevels/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point } = req.body;
    try {
        const [inventoryLevelCheck] = await pool.query('SELECT il.* FROM InventoryLevels il JOIN Warehouses w ON il.warehouse_id = w.warehouse_id JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE il.inventory_id = ? AND c.main_user_id = ?', [id, req.mainUserId]);
        if (inventoryLevelCheck.length === 0) return res.status(404).json({ message: 'Inventory level not found or not authorized.' });

        const [result] = await pool.query('UPDATE InventoryLevels SET product_id = ?, warehouse_id = ?, quantity_on_hand = ?, min_stock_level = ?, reorder_point = ? WHERE inventory_id = ?', [product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Inventory level not found or no changes made' });
        res.json({ message: 'Inventory level updated successfully' });
    } catch (err) {
        console.error('Error updating inventory level:', err);
        res.status(500).json({ message: 'Error updating inventory level', error: err.message });
    }
});

app.delete('/api/inventorylevels/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [inventoryLevelCheck] = await pool.query('SELECT il.* FROM InventoryLevels il JOIN Warehouses w ON il.warehouse_id = w.warehouse_id JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE il.inventory_id = ? AND c.main_user_id = ?', [id, req.mainUserId]);
        if (inventoryLevelCheck.length === 0) return res.status(404).json({ message: 'Inventory level not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM InventoryLevels WHERE inventory_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Inventory level not found' });
        res.json({ message: 'Inventory level deleted successfully' });
    } catch (err) {
        console.error('Error deleting inventory level:', err);
        res.status(500).json({ message: 'Error deleting inventory level', error: err.message });
    }
});

// PurchaseOrders API
app.get('/api/purchaseorders', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM PurchaseOrders';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching purchase orders:', err);
        res.status(500).json({ message: 'Error fetching purchase orders', error: err.message });
    }
});

app.get('/api/purchaseorders/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM PurchaseOrders WHERE po_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Purchase order not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching purchase order:', err);
        res.status(500).json({ message: 'Error fetching purchase order', error: err.message });
    }
});

app.post('/api/purchaseorders', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { supplier_id, order_date, delivery_date, total_amount, status, user_id, items } = req.body;
    if (!supplier_id || !order_date || !total_amount || !user_id || !items || items.length === 0) {
        return res.status(400).json({ message: 'Supplier ID, order date, total amount, user ID, and at least one item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [userCheck] = await connection.query('SELECT user_id FROM Users WHERE user_id = ? AND (main_user_id = ? OR user_id = ?)', [user_id, req.mainUserId, req.mainUserId]);
        if (userCheck.length === 0) return res.status(403).json({ message: 'User not authorized for this purchase order.' });

        const [poResult] = await connection.query(
            'INSERT INTO PurchaseOrders (supplier_id, order_date, delivery_date, total_amount, status, user_id, main_user_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [supplier_id, order_date, delivery_date, total_amount, status, user_id, req.mainUserId]
        );
        const poId = poResult.insertId;

        for (const item of items) {
            await connection.query(
                'INSERT INTO PurchaseOrderItems (po_id, product_id, quantity, unit_cost, subtotal) VALUES (?, ?, ?, ?, ?)',
                [poId, item.product_id, item.quantity, item.unit_cost, item.subtotal]
            );
        }

        await connection.commit();
        res.status(201).json({ message: 'Purchase order created successfully', poId: poId });
    } catch (err) {
        if (connection) await connection.rollback();
        console.error('Error creating purchase order:', err);
        res.status(500).json({ message: 'Error creating purchase order', error: err.message });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/purchaseorders/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { supplier_id, order_date, delivery_date, total_amount, status, user_id } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE PurchaseOrders SET supplier_id = ?, order_date = ?, delivery_date = ?, total_amount = ?, status = ?, user_id = ? WHERE po_id = ? AND main_user_id = ?',
            [supplier_id, order_date, delivery_date, total_amount, status, user_id, id, req.mainUserId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Purchase order not found, not authorized, or no changes made' });
        res.json({ message: 'Purchase order updated successfully' });
    } catch (err) {
        console.error('Error updating purchase order:', err);
        res.status(500).json({ message: 'Error updating purchase order', error: err.message });
    }
});

app.delete('/api/purchaseorders/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE PurchaseOrders SET status = "Cancelled" WHERE po_id = ? AND main_user_id = ?', [id, req.mainUserId]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Purchase order not found or not authorized' });
        res.json({ message: 'Purchase order cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling purchase order:', err);
        res.status(500).json({ message: 'Error cancelling purchase order', error: err.message });
    }
});

// PurchaseOrderItems API
app.get('/api/purchaseorderitems', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT poi.* FROM PurchaseOrderItems poi JOIN PurchaseOrders po ON poi.po_id = po.po_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE po.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching purchase order items:', err);
        res.status(500).json({ message: 'Error fetching purchase order items', error: err.message });
    }
});

app.get('/api/purchaseorderitems/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT poi.* FROM PurchaseOrderItems poi JOIN PurchaseOrders po ON poi.po_id = po.po_id WHERE poi.po_item_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND po.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Purchase order item not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching purchase order item:', err);
        res.status(500).json({ message: 'Error fetching purchase order item', error: err.message });
    }
});

// GoodsReceipts API
app.get('/api/goodsreceipts', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM GoodsReceipts';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching goods receipts:', err);
        res.status(500).json({ message: 'Error fetching goods receipts', error: err.message });
    }
});

app.get('/api/goodsreceipts/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM GoodsReceipts WHERE gr_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Goods receipt not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching goods receipt:', err);
        res.status(500).json({ message: 'Error fetching goods receipt', error: err.message });
    }
});

app.post('/api/goodsreceipts', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { po_id, warehouse_id, user_id, items } = req.body;
    if (!warehouse_id || !user_id || !items || items.length === 0) {
        return res.status(400).json({ message: 'Warehouse ID, user ID, and at least one item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [userCheck] = await connection.query('SELECT user_id FROM Users WHERE user_id = ? AND (main_user_id = ? OR user_id = ?)', [user_id, req.mainUserId, req.mainUserId]);
        if (userCheck.length === 0) return res.status(403).json({ message: 'User not authorized for this goods receipt.' });

        const [warehouseCheck] = await connection.query('SELECT w.* FROM Warehouses w JOIN Branches b ON w.branch_id = b.branch_id JOIN Companies c ON b.company_id = c.company_id WHERE w.warehouse_id = ? AND c.main_user_id = ?', [warehouse_id, req.mainUserId]);
        if (warehouseCheck.length === 0) return res.status(403).json({ message: 'Warehouse not found or not authorized for this goods receipt.' });

        const [grResult] = await connection.query(
            'INSERT INTO GoodsReceipts (po_id, warehouse_id, user_id, main_user_id) VALUES (?, ?, ?, ?)',
            [po_id, warehouse_id, user_id, req.mainUserId]
        );
        const grId = grResult.insertId;

        for (const item of items) {
            await connection.query(
                'INSERT INTO GoodsReceiptItems (gr_id, product_id, quantity_received) VALUES (?, ?, ?)',
                [grId, item.product_id, item.quantity_received]
            );
            await connection.query(
                'INSERT INTO InventoryTransactions (product_id, warehouse_id, transaction_type, quantity_change, reference_doc_type, reference_doc_id, user_id, description, main_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [item.product_id, warehouse_id, 'Purchase', item.quantity_received, 'GoodsReceipt', grId, user_id, `Goods Receipt for GR ${grId}`, req.mainUserId]
            );
            await connection.query(
                'UPDATE InventoryLevels SET quantity_on_hand = quantity_on_hand + ? WHERE product_id = ? AND warehouse_id = ?',
                [item.quantity_received, item.product_id, warehouse_id]
            );
        }

        await connection.commit();
        res.status(201).json({ message: 'Goods receipt created successfully', grId: grId });
    } catch (err) {
        if (connection) await connection.rollback();
        console.error('Error creating goods receipt:', err);
        res.status(500).json({ message: 'Error creating goods receipt', error: err.message });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/goodsreceipts/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { po_id, warehouse_id, receipt_date, user_id } = req.body;
    try {
        const [result] = await pool.query('UPDATE GoodsReceipts SET po_id = ?, warehouse_id = ?, receipt_date = ?, user_id = ? WHERE gr_id = ? AND main_user_id = ?', [po_id, warehouse_id, receipt_date, user_id, id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Goods receipt not found, not authorized, or no changes made' });
        res.json({ message: 'Goods receipt updated successfully' });
    } catch (err) {
        console.error('Error updating goods receipt:', err);
        res.status(500).json({ message: 'Error updating goods receipt', error: err.message });
    }
});

app.delete('/api/goodsreceipts/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM GoodsReceipts WHERE gr_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Goods receipt not found or not authorized' });
        res.json({ message: 'Goods receipt deleted successfully' });
    } catch (err) {
        console.error('Error deleting goods receipt:', err);
        res.status(500).json({ message: 'Error deleting goods receipt', error: err.message });
    }
});

// GoodsReceiptItems API
app.get('/api/goodsreceiptitems', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT gri.* FROM GoodsReceiptItems gri JOIN GoodsReceipts gr ON gri.gr_id = gr.gr_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE gr.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching goods receipt items:', err);
        res.status(500).json({ message: 'Error fetching goods receipt items', error: err.message });
    }
});

app.get('/api/goodsreceiptitems/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT gri.* FROM GoodsReceiptItems gri JOIN GoodsReceipts gr ON gri.gr_id = gr.gr_id WHERE gri.gr_item_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND gr.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Goods receipt item not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching goods receipt item:', err);
        res.status(500).json({ message: 'Error fetching goods receipt item', error: err.message });
    }
});

// InventoryTransactions API (Read-only, typically generated by other modules)
app.get('/api/inventorytransactions', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM InventoryTransactions';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        query += ' ORDER BY transaction_date DESC';
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching inventory transactions:', err);
        res.status(500).json({ message: 'Error fetching inventory transactions', error: err.message });
    }
});

app.get('/api/inventorytransactions/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM InventoryTransactions WHERE transaction_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Inventory transaction not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching inventory transaction:', err);
        res.status(500).json({ message: 'Error fetching inventory transaction', error: err.message });
    }
});


// --- ERP Module Tables (Financial Management) ---

// ChartOfAccounts API
app.get('/api/chartofaccounts', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT coa.* FROM ChartOfAccounts coa';
        const params = [];
        if (req.mainUserId) {
            query += ' JOIN JournalEntryLines jel ON coa.account_id = jel.account_id JOIN JournalEntries je ON jel.entry_id = je.entry_id WHERE je.main_user_id = ? GROUP BY coa.account_id';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching chart of accounts:', err);
        res.status(500).json({ message: 'Error fetching chart of accounts', error: err.message });
    }
});

app.get('/api/chartofaccounts/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT coa.* FROM ChartOfAccounts coa WHERE coa.account_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND coa.account_id IN (SELECT account_id FROM JournalEntryLines jel JOIN JournalEntries je ON jel.entry_id = je.entry_id WHERE je.main_user_id = ?)';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Account not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching account:', err);
        res.status(500).json({ message: 'Error fetching account', error: err.message });
    }
});

app.post('/api/chartofaccounts', authenticateToken, authorizeMainUser, async (req, res) => {
    const { account_code, account_name, account_type, parent_account_id, is_active } = req.body;
    if (!account_code || !account_name || !account_type) return res.status(400).json({ message: 'Account code, name, and type are required.' });
    try {
        const [result] = await pool.query('INSERT INTO ChartOfAccounts (account_code, account_name, account_type, parent_account_id, is_active) VALUES (?, ?, ?, ?, ?)', [account_code, account_name, account_type, parent_account_id, is_active]);
        res.status(201).json({ message: 'Account created successfully', accountId: result.insertId });
    } catch (err) {
        console.error('Error creating account:', err);
        res.status(500).json({ message: 'Error creating account', error: err.message });
    }
});

app.put('/api/chartofaccounts/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { account_code, account_name, account_type, parent_account_id, is_active } = req.body;
    try {
        if (req.mainUserId) {
            const [accountCheck] = await pool.query('SELECT coa.* FROM ChartOfAccounts coa JOIN JournalEntryLines jel ON coa.account_id = jel.account_id JOIN JournalEntries je ON jel.entry_id = je.entry_id WHERE coa.account_id = ? AND je.main_user_id = ? GROUP BY coa.account_id', [id, req.mainUserId]);
            if (accountCheck.length === 0) {
                return res.status(404).json({ message: 'Account not found or not authorized.' });
            }
        }
        const [result] = await pool.query('UPDATE ChartOfAccounts SET account_code = ?, account_name = ?, account_type = ?, parent_account_id = ?, is_active = ? WHERE account_id = ?', [account_code, account_name, account_type, parent_account_id, is_active, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Account not found or no changes made' });
        res.json({ message: 'Account updated successfully' });
    } catch (err) {
        console.error('Error updating account:', err);
        res.status(500).json({ message: 'Error updating account', error: err.message });
    }
});

app.delete('/api/chartofaccounts/:id', authenticateToken, authorizeMainUser, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        if (req.mainUserId) {
            const [accountCheck] = await pool.query('SELECT coa.* FROM ChartOfAccounts coa JOIN JournalEntryLines jel ON coa.account_id = jel.account_id JOIN JournalEntries je ON jel.entry_id = je.entry_id WHERE coa.account_id = ? AND je.main_user_id = ? GROUP BY coa.account_id', [id, req.mainUserId]);
            if (accountCheck.length === 0) {
                return res.status(404).json({ message: 'Account not found or not authorized.' });
            }
        }
        const [result] = await pool.query('UPDATE ChartOfAccounts SET is_active = FALSE WHERE account_id = ?', [id]); // Soft delete
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Account not found' });
        res.json({ message: 'Account deactivated successfully' });
    } catch (err) {
        console.error('Error deactivating account:', err);
        res.status(500).json({ message: 'Error deactivating account', error: err.message });
    }
});

// JournalEntries API
app.get('/api/journalentries', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM JournalEntries';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        query += ' ORDER BY entry_date DESC';
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching journal entries:', err);
        res.status(500).json({ message: 'Error fetching journal entries', error: err.message });
    }
});

app.get('/api/journalentries/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM JournalEntries WHERE entry_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Journal entry not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching journal entry:', err);
        res.status(500).json({ message: 'Error fetching journal entry', error: err.message });
    }
});

app.post('/api/journalentries', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { entry_date, description, reference_type, reference_id, user_id, lines } = req.body;
    if (!entry_date || !user_id || !lines || lines.length === 0) {
        return res.status(400).json({ message: 'Entry date, user ID, and at least one line item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [userCheck] = await connection.query('SELECT user_id FROM Users WHERE user_id = ? AND (main_user_id = ? OR user_id = ?)', [user_id, req.mainUserId, req.mainUserId]);
        if (userCheck.length === 0) return res.status(403).json({ message: 'User not authorized for this journal entry.' });

        const [entryResult] = await connection.query(
            'INSERT INTO JournalEntries (entry_date, description, reference_type, reference_id, user_id, main_user_id) VALUES (?, ?, ?, ?, ?, ?)',
            [entry_date, description, reference_type, reference_id, user_id, req.mainUserId]
        );
        const entryId = entryResult.insertId;

        for (const line of lines) {
            await connection.query(
                'INSERT INTO JournalEntryLines (entry_id, account_id, debit, credit, memo) VALUES (?, ?, ?, ?, ?)',
                [entryId, line.account_id, line.debit, line.credit, line.memo]
            );
        }

        await connection.commit();
        res.status(201).json({ message: 'Journal entry created successfully', entryId: entryId });
    } catch (err) {
        if (connection) await connection.rollback();
        console.error('Error creating journal entry:', err);
        res.status(500).json({ message: 'Error creating journal entry', error: err.message });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/journalentries/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { entry_date, description, reference_type, reference_id, user_id } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE JournalEntries SET entry_date = ?, description = ?, reference_type = ?, reference_id = ?, user_id = ? WHERE entry_id = ? AND main_user_id = ?',
            [entry_date, description, reference_type, reference_id, user_id, id, req.mainUserId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Journal entry not found, not authorized, or no changes made' });
        res.json({ message: 'Journal entry updated successfully' });
    } catch (err) {
        console.error('Error updating journal entry:', err);
        res.status(500).json({ message: 'Error updating journal entry', error: err.message });
    }
});

app.delete('/api/journalentries/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM JournalEntries WHERE entry_id = ? AND main_user_id = ?', [id, req.mainUserId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Journal entry not found or not authorized' });
        res.json({ message: 'Journal entry deleted successfully' });
    } catch (err) {
        console.error('Error deleting journal entry:', err);
        res.status(500).json({ message: 'Error deleting journal entry', error: err.message });
    }
});

// JournalEntryLines API
app.get('/api/journalentrylines', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT jel.* FROM JournalEntryLines jel JOIN JournalEntries je ON jel.entry_id = je.entry_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE je.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching journal entry lines:', err);
        res.status(500).json({ message: 'Error fetching journal entry lines', error: err.message });
    }
});

app.get('/api/journalentrylines/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT jel.* FROM JournalEntryLines jel JOIN JournalEntries je ON jel.entry_id = je.entry_id WHERE jel.line_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND je.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Journal entry line not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching journal entry line:', err);
        res.status(500).json({ message: 'Error fetching journal entry line', error: err.message });
    }
});

// Invoices API
app.get('/api/invoices', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT * FROM Invoices';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching invoices:', err);
        res.status(500).json({ message: 'Error fetching invoices', error: err.message });
    }
});

app.get('/api/invoices/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT * FROM Invoices WHERE invoice_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Invoice not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching invoice:', err);
        res.status(500).json({ message: 'Error fetching invoice', error: err.message });
    }
});

app.post('/api/invoices', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id } = req.body;
    if (!invoice_date || !total_amount || (!customer_id && !supplier_id)) {
        return res.status(400).json({ message: 'Invoice date, total amount, and either customer ID or supplier ID are required.' });
    }
    try {
        const [result] = await pool.query(
            'INSERT INTO Invoices (invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id, main_user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id, req.mainUserId]
        );
        res.status(201).json({ message: 'Invoice created successfully', invoiceId: result.insertId });
    } catch (err) {
        console.error('Error creating invoice:', err);
        res.status(500).json({ message: 'Error creating invoice', error: err.message });
    }
});

app.put('/api/invoices/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE Invoices SET invoice_date = ?, due_date = ?, customer_id = ?, supplier_id = ?, total_amount = ?, status = ?, reference_order_id = ? WHERE invoice_id = ? AND main_user_id = ?',
            [invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id, id, req.mainUserId]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Invoice not found, not authorized, or no changes made' });
        res.json({ message: 'Invoice updated successfully' });
    } catch (err) {
        console.error('Error updating invoice:', err);
        res.status(500).json({ message: 'Error updating invoice', error: err.message });
    }
});

app.delete('/api/invoices/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE Invoices SET status = "Cancelled" WHERE invoice_id = ? AND main_user_id = ?', [id, req.mainUserId]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Invoice not found or not authorized' });
        res.json({ message: 'Invoice cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling invoice:', err);
        res.status(500).json({ message: 'Error cancelling invoice', error: err.message });
    }
});

// PaymentsReceived API
app.get('/api/paymentsreceived', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT pr.* FROM PaymentsReceived pr JOIN Invoices i ON pr.invoice_id = i.invoice_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE i.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payments received:', err);
        res.status(500).json({ message: 'Error fetching payments received', error: err.message });
    }
});

app.get('/api/paymentsreceived/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT pr.* FROM PaymentsReceived pr JOIN Invoices i ON pr.invoice_id = i.invoice_id WHERE pr.receipt_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND i.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Payment received not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payment received:', err);
        res.status(500).json({ message: 'Error fetching payment received', error: err.message });
    }
});

app.post('/api/paymentsreceived', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { invoice_id, amount_received, payment_method, user_id } = req.body;
    if (!invoice_id || !amount_received || !payment_method) {
        return res.status(400).json({ message: 'Invoice ID, amount received, and payment method are required.' });
    }
    try {
        const [invoiceCheck] = await pool.query('SELECT invoice_id FROM Invoices WHERE invoice_id = ? AND main_user_id = ?', [invoice_id, req.mainUserId]);
        if (invoiceCheck.length === 0) return res.status(403).json({ message: 'Invoice not found or not authorized for this payment received.' });

        const [result] = await pool.query(
            'INSERT INTO PaymentsReceived (invoice_id, amount_received, payment_method, user_id) VALUES (?, ?, ?, ?)',
            [invoice_id, amount_received, payment_method, user_id]
        );
        res.status(201).json({ message: 'Payment received recorded successfully', receiptId: result.insertId });
    } catch (err) {
        console.error('Error recording payment received:', err);
        res.status(500).json({ message: 'Error recording payment received', error: err.message });
    }
});

app.put('/api/paymentsreceived/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { invoice_id, amount_received, receipt_date, payment_method, user_id } = req.body;
    try {
        const [paymentReceivedCheck] = await pool.query('SELECT pr.* FROM PaymentsReceived pr JOIN Invoices i ON pr.invoice_id = i.invoice_id WHERE pr.receipt_id = ? AND i.main_user_id = ?', [id, req.mainUserId]);
        if (paymentReceivedCheck.length === 0) return res.status(404).json({ message: 'Payment received not found or not authorized.' });

        const [result] = await pool.query(
            'UPDATE PaymentsReceived SET invoice_id = ?, amount_received = ?, receipt_date = ?, payment_method = ?, user_id = ? WHERE receipt_id = ?',
            [invoice_id, amount_received, receipt_date, payment_method, user_id, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment received not found or no changes made' });
        res.json({ message: 'Payment received updated successfully' });
    } catch (err) {
        console.error('Error updating payment received:', err);
        res.status(500).json({ message: 'Error updating payment received', error: err.message });
    }
});

app.delete('/api/paymentsreceived/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [paymentReceivedCheck] = await pool.query('SELECT pr.* FROM PaymentsReceived pr JOIN Invoices i ON pr.invoice_id = i.invoice_id WHERE pr.receipt_id = ? AND i.main_user_id = ?', [id, req.mainUserId]);
        if (paymentReceivedCheck.length === 0) return res.status(404).json({ message: 'Payment received not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM PaymentsReceived WHERE receipt_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment received not found' });
        res.json({ message: 'Payment received deleted successfully' });
    } catch (err) {
        console.error('Error deleting payment received:', err);
        res.status(500).json({ message: 'Error deleting payment received', error: err.message });
    }
});

// PaymentsMade API
app.get('/api/paymentsmade', authenticateToken, authorizeDataOwner, async (req, res) => {
    try {
        let query = 'SELECT pm.* FROM PaymentsMade pm JOIN Invoices i ON pm.invoice_id = i.invoice_id';
        const params = [];
        if (req.mainUserId) {
            query += ' WHERE i.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payments made:', err);
        res.status(500).json({ message: 'Error fetching payments made', error: err.message });
    }
});

app.get('/api/paymentsmade/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        let query = 'SELECT pm.* FROM PaymentsMade pm JOIN Invoices i ON pm.invoice_id = i.invoice_id WHERE pm.payment_id = ?';
        const params = [id];
        if (req.mainUserId) {
            query += ' AND i.main_user_id = ?';
            params.push(req.mainUserId);
        }
        const [rows] = await pool.query(query, params);
        if (rows.length === 0) return res.status(404).json({ message: 'Payment made not found or not authorized' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payment made:', err);
        res.status(500).json({ message: 'Error fetching payment made', error: err.message });
    }
});

app.post('/api/paymentsmade', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { invoice_id, amount_paid, payment_method, user_id } = req.body;
    if (!invoice_id || !amount_paid || !payment_method) {
        return res.status(400).json({ message: 'Invoice ID, amount paid, and payment method are required.' });
    }
    try {
        const [invoiceCheck] = await pool.query('SELECT invoice_id FROM Invoices WHERE invoice_id = ? AND main_user_id = ?', [invoice_id, req.mainUserId]);
        if (invoiceCheck.length === 0) return res.status(403).json({ message: 'Invoice not found or not authorized for this payment made.' });

        const [result] = await pool.query(
            'INSERT INTO PaymentsMade (invoice_id, amount_paid, payment_method, user_id) VALUES (?, ?, ?, ?)',
            [invoice_id, amount_paid, payment_method, user_id]
        );
        res.status(201).json({ message: 'Payment made recorded successfully', paymentId: result.insertId });
    } catch (err) {
        console.error('Error recording payment made:', err);
        res.status(500).json({ message: 'Error recording payment made', error: err.message });
    }
});

app.put('/api/paymentsmade/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    const { invoice_id, amount_paid, payment_date, payment_method, user_id } = req.body;
    try {
        const [paymentMadeCheck] = await pool.query('SELECT pm.* FROM PaymentsMade pm JOIN Invoices i ON pm.invoice_id = i.invoice_id WHERE pm.payment_id = ? AND i.main_user_id = ?', [id, req.mainUserId]);
        if (paymentMadeCheck.length === 0) return res.status(404).json({ message: 'Payment made not found or not authorized.' });

        const [result] = await pool.query(
            'UPDATE PaymentsMade SET invoice_id = ?, amount_paid = ?, payment_date = ?, payment_method = ?, user_id = ? WHERE payment_id = ?',
            [invoice_id, amount_paid, payment_date, payment_method, user_id, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment made not found or no changes made' });
        res.json({ message: 'Payment made updated successfully' });
    } catch (err) {
        console.error('Error updating payment made:', err);
        res.status(500).json({ message: 'Error updating payment made', error: err.message });
    }
});

app.delete('/api/paymentsmade/:id', authenticateToken, authorizeDataOwner, async (req, res) => {
    const { id } = req.params;
    try {
        const [paymentMadeCheck] = await pool.query('SELECT pm.* FROM PaymentsMade pm JOIN Invoices i ON pm.invoice_id = i.invoice_id WHERE pm.payment_id = ? AND i.main_user_id = ?', [id, req.mainUserId]);
        if (paymentMadeCheck.length === 0) return res.status(404).json({ message: 'Payment made not found or not authorized.' });

        const [result] = await pool.query('DELETE FROM PaymentsMade WHERE payment_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment made not found' });
        res.json({ message: 'Payment made deleted successfully' });
    } catch (err) {
        console.error('Error deleting payment made:', err);
        res.status(500).json({ message: 'Error deleting payment made', error: err.message });
    }
});


// -----------------------------------------------------
// Start the server
// -----------------------------------------------------
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Access API at http://localhost:${PORT}`);
});

// Error handling for unmatched routes
app.use((req, res, next) => {
    res.status(404).send('404: Page Not Found');
});

// Generic error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});