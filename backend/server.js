const express = require('express');
const mysql = require('mysql2/promise'); // Using mysql2/promise for async/await
const dotenv = require('dotenv');
const cors = require('cors'); // For handling Cross-Origin Resource Sharing

// Load environment variables from .env file
dotenv.config();

// --- Debugging: Environment Variables Loaded ---
// These logs help verify that your .env file is loaded correctly.
console.log('--- Environment Variables Loaded ---');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '********' : 'NOT SET'); // Mask password for security
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('PORT (App):', process.env.PORT);
console.log('----------------------------------');
// --- End Debugging ---

// Initialize Express app and define port
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors()); // Enable CORS for all routes (important for frontend communication)
app.use(express.json()); // Enable parsing JSON request bodies

// -----------------------------------------------------
// Database Connection Pool
// Create a connection pool to manage database connections efficiently.
// This is crucial for performance in a production environment.
// -----------------------------------------------------
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT, // Use DB_PORT from .env
    waitForConnections: true, // Wait for connections to become available
    connectionLimit: 10,      // Max number of connections in the pool
    queueLimit: 0             // Unlimited queueing for connections
});

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('Connected to MySQL database successfully!');
        connection.release(); // Release the connection back to the pool
    })
    .catch(err => {
        console.error('Failed to connect to MySQL database:', err.message);
        // Exit the process if database connection fails, as the app cannot function without it.
        process.exit(1);
    });

// -----------------------------------------------------
// API Routes
// Comprehensive API routes for all specified tables with basic CRUD operations.
// -----------------------------------------------------

// Basic route for checking API status
app.get('/', (req, res) => {
    res.send('Welcome to the ERP/POS/HR Backend API!');
});

// --- Core ERP Tables ---

// Companies API
app.get('/api/companies', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Companies');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching companies:', err);
        res.status(500).json({ message: 'Error fetching companies', error: err.message });
    }
});

app.get('/api/companies/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Companies WHERE company_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Company not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching company:', err);
        res.status(500).json({ message: 'Error fetching company', error: err.message });
    }
});

app.post('/api/companies', async (req, res) => {
    const { company_name, address, tax_id, phone, email } = req.body;
    if (!company_name) return res.status(400).json({ message: 'Company name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Companies (company_name, address, tax_id, phone, email) VALUES (?, ?, ?, ?, ?)', [company_name, address, tax_id, phone, email]);
        res.status(201).json({ message: 'Company created successfully', companyId: result.insertId });
    } catch (err) {
        console.error('Error creating company:', err);
        res.status(500).json({ message: 'Error creating company', error: err.message });
    }
});

app.put('/api/companies/:id', async (req, res) => {
    const { id } = req.params;
    const { company_name, address, tax_id, phone, email } = req.body;
    try {
        const [result] = await pool.query('UPDATE Companies SET company_name = ?, address = ?, tax_id = ?, phone = ?, email = ? WHERE company_id = ?', [company_name, address, tax_id, phone, email, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Company not found or no changes made' });
        res.json({ message: 'Company updated successfully' });
    } catch (err) {
        console.error('Error updating company:', err);
        res.status(500).json({ message: 'Error updating company', error: err.message });
    }
});

app.delete('/api/companies/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Companies WHERE company_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Company not found' });
        res.json({ message: 'Company deleted successfully' });
    } catch (err) {
        console.error('Error deleting company:', err);
        res.status(500).json({ message: 'Error deleting company', error: err.message });
    }
});

// Branches API
app.get('/api/branches', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Branches');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching branches:', err);
        res.status(500).json({ message: 'Error fetching branches', error: err.message });
    }
});

app.get('/api/branches/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Branches WHERE branch_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Branch not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching branch:', err);
        res.status(500).json({ message: 'Error fetching branch', error: err.message });
    }
});

app.post('/api/branches', async (req, res) => {
    const { company_id, branch_name, address, phone } = req.body;
    if (!company_id || !branch_name) return res.status(400).json({ message: 'Company ID and branch name are required.' });
    try {
        const [result] = await pool.query('INSERT INTO Branches (company_id, branch_name, address, phone) VALUES (?, ?, ?, ?)', [company_id, branch_name, address, phone]);
        res.status(201).json({ message: 'Branch created successfully', branchId: result.insertId });
    } catch (err) {
        console.error('Error creating branch:', err);
        res.status(500).json({ message: 'Error creating branch', error: err.message });
    }
});

app.put('/api/branches/:id', async (req, res) => {
    const { id } = req.params;
    const { company_id, branch_name, address, phone } = req.body;
    try {
        const [result] = await pool.query('UPDATE Branches SET company_id = ?, branch_name = ?, address = ?, phone = ? WHERE branch_id = ?', [company_id, branch_name, address, phone, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Branch not found or no changes made' });
        res.json({ message: 'Branch updated successfully' });
    } catch (err) {
        console.error('Error updating branch:', err);
        res.status(500).json({ message: 'Error updating branch', error: err.message });
    }
});

app.delete('/api/branches/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Branches WHERE branch_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Branch not found' });
        res.json({ message: 'Branch deleted successfully' });
    } catch (err) {
        console.error('Error deleting branch:', err);
        res.status(500).json({ message: 'Error deleting branch', error: err.message });
    }
});

// Roles API
app.get('/api/roles', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Roles');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching roles:', err);
        res.status(500).json({ message: 'Error fetching roles', error: err.message });
    }
});

app.get('/api/roles/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Roles WHERE role_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Role not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching role:', err);
        res.status(500).json({ message: 'Error fetching role', error: err.message });
    }
});

app.post('/api/roles', async (req, res) => {
    const { role_name, description } = req.body;
    if (!role_name) return res.status(400).json({ message: 'Role name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Roles (role_name, description) VALUES (?, ?)', [role_name, description]);
        res.status(201).json({ message: 'Role created successfully', roleId: result.insertId });
    } catch (err) {
        console.error('Error creating role:', err);
        res.status(500).json({ message: 'Error creating role', error: err.message });
    }
});

app.put('/api/roles/:id', async (req, res) => {
    const { id } = req.params;
    const { role_name, description } = req.body;
    try {
        const [result] = await pool.query('UPDATE Roles SET role_name = ?, description = ? WHERE role_id = ?', [role_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Role not found or no changes made' });
        res.json({ message: 'Role updated successfully' });
    } catch (err) {
        console.error('Error updating role:', err);
        res.status(500).json({ message: 'Error updating role', error: err.message });
    }
});

app.delete('/api/roles/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Roles WHERE role_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Role not found' });
        res.json({ message: 'Role deleted successfully' });
    } catch (err) {
        console.error('Error deleting role:', err);
        res.status(500).json({ message: 'Error deleting role', error: err.message });
    }
});

// Permissions API
app.get('/api/permissions', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Permissions');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching permissions:', err);
        res.status(500).json({ message: 'Error fetching permissions', error: err.message });
    }
});

app.get('/api/permissions/:id', async (req, res) => {
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

app.post('/api/permissions', async (req, res) => {
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

app.put('/api/permissions/:id', async (req, res) => {
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

app.delete('/api/permissions/:id', async (req, res) => {
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

// RolePermissions API (Many-to-Many relationship)
app.get('/api/rolepermissions', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT rp.role_id, r.role_name, rp.permission_id, p.permission_name FROM RolePermissions rp JOIN Roles r ON rp.role_id = r.role_id JOIN Permissions p ON rp.permission_id = p.permission_id');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching role permissions:', err);
        res.status(500).json({ message: 'Error fetching role permissions', error: err.message });
    }
});

app.post('/api/rolepermissions', async (req, res) => {
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

app.delete('/api/rolepermissions', async (req, res) => {
    const { role_id, permission_id } = req.body; // Use body for DELETE with multiple identifiers
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
app.get('/api/departments', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Departments');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching departments:', err);
        res.status(500).json({ message: 'Error fetching departments', error: err.message });
    }
});

app.get('/api/departments/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Departments WHERE department_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Department not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching department:', err);
        res.status(500).json({ message: 'Error fetching department', error: err.message });
    }
});

app.post('/api/departments', async (req, res) => {
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

app.put('/api/departments/:id', async (req, res) => {
    const { id } = req.params;
    const { department_name } = req.body;
    try {
        const [result] = await pool.query('UPDATE Departments SET department_name = ? WHERE department_id = ?', [department_name, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Department not found or no changes made' });
        res.json({ message: 'Department updated successfully' });
    } catch (err) {
        console.error('Error updating department:', err);
        res.status(500).json({ message: 'Error updating department', error: err.message });
    }
});

app.delete('/api/departments/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Departments WHERE department_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Department not found' });
        res.json({ message: 'Department deleted successfully' });
    } catch (err) {
        console.error('Error deleting department:', err);
        res.status(500).json({ message: 'Error deleting department', error: err.message });
    }
});

// Positions API
app.get('/api/positions', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Positions');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching positions:', err);
        res.status(500).json({ message: 'Error fetching positions', error: err.message });
    }
});

app.get('/api/positions/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Positions WHERE position_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Position not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching position:', err);
        res.status(500).json({ message: 'Error fetching position', error: err.message });
    }
});

app.post('/api/positions', async (req, res) => {
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

app.put('/api/positions/:id', async (req, res) => {
    const { id } = req.params;
    const { position_name, description } = req.body;
    try {
        const [result] = await pool.query('UPDATE Positions SET position_name = ?, description = ? WHERE position_id = ?', [position_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Position not found or no changes made' });
        res.json({ message: 'Position updated successfully' });
    } catch (err) {
        console.error('Error updating position:', err);
        res.status(500).json({ message: 'Error updating position', error: err.message });
    }
});

app.delete('/api/positions/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Positions WHERE position_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Position not found' });
        res.json({ message: 'Position deleted successfully' });
    } catch (err) {
        console.error('Error deleting position:', err);
        res.status(500).json({ message: 'Error deleting position', error: err.message });
    }
});

// Employees API (HR Module)
app.get('/api/employees', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Employees'); // Removed WHERE employment_status = "Active" to get all
        res.json(rows);
    } catch (err) {
        console.error('Error fetching employees:', err);
        res.status(500).json({ message: 'Error fetching employees', error: err.message });
    }
});

app.get('/api/employees/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Employees WHERE employee_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Employee not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching employee:', err);
        res.status(500).json({ message: 'Error fetching employee', error: err.message });
    }
});

app.post('/api/employees', async (req, res) => {
    const { user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base } = req.body;
    if (!first_name || !last_name || !thai_id_no || !hire_date) return res.status(400).json({ message: 'First name, last name, Thai ID, and hire date are required.' });
    try {
        const [result] = await pool.query(
            'INSERT INTO Employees (user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base]
        );
        res.status(201).json({ message: 'Employee created successfully', employeeId: result.insertId });
    } catch (err) {
        console.error('Error creating employee:', err);
        res.status(500).json({ message: 'Error creating employee', error: err.message });
    }
});

app.put('/api/employees/:id', async (req, res) => {
    const { id } = req.params;
    const { user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE Employees SET user_id = ?, first_name = ?, last_name = ?, thai_id_no = ?, date_of_birth = ?, gender = ?, address = ?, phone = ?, email = ?, department_id = ?, position_id = ?, employment_status = ?, hire_date = ?, salary_base = ? WHERE employee_id = ?',
            [user_id, first_name, last_name, thai_id_no, date_of_birth, gender, address, phone, email, department_id, position_id, employment_status, hire_date, salary_base, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee not found or no changes made' });
        res.json({ message: 'Employee updated successfully' });
    } catch (err) {
        console.error('Error updating employee:', err);
        res.status(500).json({ message: 'Error updating employee', error: err.message });
    }
});

app.delete('/api/employees/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE Employees SET employment_status = "Terminated" WHERE employee_id = ?', [id]); // Soft delete
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee not found' });
        res.json({ message: 'Employee terminated successfully (soft deleted)' });
    } catch (err) {
        console.error('Error terminating employee:', err);
        res.status(500).json({ message: 'Error terminating employee', error: err.message });
    }
});

// Users API
app.get('/api/users', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT user_id, username, employee_id, role_id, is_active FROM Users'); // Exclude password_hash
        res.json(rows);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ message: 'Error fetching users', error: err.message });
    }
});

app.get('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT user_id, username, employee_id, role_id, is_active FROM Users WHERE user_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ message: 'Error fetching user', error: err.message });
    }
});

app.post('/api/users', async (req, res) => {
    const { username, password_hash, employee_id, role_id, is_active } = req.body;
    if (!username || !password_hash || !role_id) return res.status(400).json({ message: 'Username, password, and role ID are required.' });
    // In a real app, hash password here before inserting
    try {
        const [result] = await pool.query('INSERT INTO Users (username, password_hash, employee_id, role_id, is_active) VALUES (?, ?, ?, ?, ?)', [username, password_hash, employee_id, role_id, is_active]);
        res.status(201).json({ message: 'User created successfully', userId: result.insertId });
    } catch (err) {
        console.error('Error creating user:', err);
        res.status(500).json({ message: 'Error creating user', error: err.message });
    }
});

app.put('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { username, password_hash, employee_id, role_id, is_active } = req.body;
    try {
        // Only update password_hash if provided
        let query = 'UPDATE Users SET username = ?, employee_id = ?, role_id = ?, is_active = ?';
        let params = [username, employee_id, role_id, is_active];
        if (password_hash) {
            query += ', password_hash = ?';
            params.push(password_hash);
        }
        query += ' WHERE user_id = ?';
        params.push(id);

        const [result] = await pool.query(query, params);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found or no changes made' });
        res.json({ message: 'User updated successfully' });
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ message: 'Error updating user', error: err.message });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE Users SET is_active = FALSE WHERE user_id = ?', [id]); // Soft delete
        if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
        res.json({ message: 'User deactivated successfully (soft deleted)' });
    } catch (err) {
        console.error('Error deactivating user:', err);
        res.status(500).json({ message: 'Error deactivating user', error: err.message });
    }
});

// AuditLogs API (Read-only, typically managed by system/triggers)
app.get('/api/auditlogs', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM AuditLogs ORDER BY timestamp DESC');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching audit logs:', err);
        res.status(500).json({ message: 'Error fetching audit logs', error: err.message });
    }
});

app.get('/api/auditlogs/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM AuditLogs WHERE log_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Audit log not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching audit log:', err);
        res.status(500).json({ message: 'Error fetching audit log', error: err.message });
    }
});


// --- POS Module Tables ---

// Products API (already defined above, extending with more robust handling)
// (GET all, GET by ID, POST, PUT, DELETE - already provided in previous version)

// Categories API
app.get('/api/categories', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Categories');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ message: 'Error fetching categories', error: err.message });
    }
});

app.get('/api/categories/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Categories WHERE category_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Category not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching category:', err);
        res.status(500).json({ message: 'Error fetching category', error: err.message });
    }
});

app.post('/api/categories', async (req, res) => {
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

app.put('/api/categories/:id', async (req, res) => {
    const { id } = req.params;
    const { category_name } = req.body;
    try {
        const [result] = await pool.query('UPDATE Categories SET category_name = ? WHERE category_id = ?', [category_name, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Category not found or no changes made' });
        res.json({ message: 'Category updated successfully' });
    } catch (err) {
        console.error('Error updating category:', err);
        res.status(500).json({ message: 'Error updating category', error: err.message });
    }
});

app.delete('/api/categories/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Categories WHERE category_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Category not found' });
        res.json({ message: 'Category deleted successfully' });
    } catch (err) {
        console.error('Error deleting category:', err);
        res.status(500).json({ message: 'Error deleting category', error: err.message });
    }
});

// Customers API
app.get('/api/customers', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Customers');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching customers:', err);
        res.status(500).json({ message: 'Error fetching customers', error: err.message });
    }
});

app.get('/api/customers/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Customers WHERE customer_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Customer not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching customer:', err);
        res.status(500).json({ message: 'Error fetching customer', error: err.message });
    }
});

app.post('/api/customers', async (req, res) => {
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

app.put('/api/customers/:id', async (req, res) => {
    const { id } = req.params;
    const { customer_name, phone, email, address } = req.body;
    try {
        const [result] = await pool.query('UPDATE Customers SET customer_name = ?, phone = ?, email = ?, address = ? WHERE customer_id = ?', [customer_name, phone, email, address, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Customer not found or no changes made' });
        res.json({ message: 'Customer updated successfully' });
    } catch (err) {
        console.error('Error updating customer:', err);
        res.status(500).json({ message: 'Error updating customer', error: err.message });
    }
});

app.delete('/api/customers/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Customers WHERE customer_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Customer not found' });
        res.json({ message: 'Customer deleted successfully' });
    } catch (err) {
        console.error('Error deleting customer:', err);
        res.status(500).json({ message: 'Error deleting customer', error: err.message });
    }
});

// SalesOrders API
app.get('/api/salesorders', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM SalesOrders');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching sales orders:', err);
        res.status(500).json({ message: 'Error fetching sales orders', error: err.message });
    }
});

app.get('/api/salesorders/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM SalesOrders WHERE order_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Sales order not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching sales order:', err);
        res.status(500).json({ message: 'Error fetching sales order', error: err.message });
    }
});

app.post('/api/salesorders', async (req, res) => {
    const { customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status, items } = req.body;
    if (!user_id || !branch_id || !net_amount || !items || items.length === 0) {
        return res.status(400).json({ message: 'User ID, Branch ID, Net Amount, and at least one item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction(); // Start transaction

        const [orderResult] = await connection.query(
            'INSERT INTO SalesOrders (customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status]
        );
        const orderId = orderResult.insertId;

        for (const item of items) {
            await connection.query(
                'INSERT INTO SalesOrderItems (order_id, product_id, quantity, unit_price, subtotal) VALUES (?, ?, ?, ?, ?)',
                [orderId, item.product_id, item.quantity, item.unit_price, item.subtotal]
            );
            // Optionally, update stock here or trigger an Inventory Transaction
            // await connection.query('UPDATE Products SET stock_quantity = stock_quantity - ? WHERE product_id = ?', [item.quantity, item.product_id]);
            // Or log to InventoryTransactions table
            await connection.query(
                'INSERT INTO InventoryTransactions (product_id, warehouse_id, transaction_type, quantity_change, reference_doc_type, reference_doc_id, user_id, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [item.product_id, branch_id, 'Sale', -item.quantity, 'SalesOrder', orderId, user_id, `Sale for Order ${orderId}`]
            );
        }

        await connection.commit(); // Commit transaction
        res.status(201).json({ message: 'Sales order created successfully', orderId: orderId });
    } catch (err) {
        if (connection) await connection.rollback(); // Rollback on error
        console.error('Error creating sales order:', err);
        res.status(500).json({ message: 'Error creating sales order', error: err.message });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/salesorders/:id', async (req, res) => {
    const { id } = req.params;
    const { customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE SalesOrders SET customer_id = ?, user_id = ?, branch_id = ?, total_amount = ?, discount_amount = ?, tax_amount = ?, net_amount = ?, status = ? WHERE order_id = ?',
            [customer_id, user_id, branch_id, total_amount, discount_amount, tax_amount, net_amount, status, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Sales order not found or no changes made' });
        res.json({ message: 'Sales order updated successfully' });
    } catch (err) {
        console.error('Error updating sales order:', err);
        res.status(500).json({ message: 'Error updating sales order', error: err.message });
    }
});

app.delete('/api/salesorders/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE SalesOrders SET status = "Canceled" WHERE order_id = ?', [id]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Sales order not found' });
        res.json({ message: 'Sales order cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling sales order:', err);
        res.status(500).json({ message: 'Error cancelling sales order', error: err.message });
    }
});

// SalesOrderItems API (Typically managed via SalesOrders, but CRUD for direct access)
app.get('/api/salesorderitems', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM SalesOrderItems');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching sales order items:', err);
        res.status(500).json({ message: 'Error fetching sales order items', error: err.message });
    }
});

app.get('/api/salesorderitems/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM SalesOrderItems WHERE order_item_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Sales order item not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching sales order item:', err);
        res.status(500).json({ message: 'Error fetching sales order item', error: err.message });
    }
});

// Payments API
app.get('/api/payments', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Payments');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payments:', err);
        res.status(500).json({ message: 'Error fetching payments', error: err.message });
    }
});

app.get('/api/payments/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Payments WHERE payment_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Payment not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payment:', err);
        res.status(500).json({ message: 'Error fetching payment', error: err.message });
    }
});

app.post('/api/payments', async (req, res) => {
    const { order_id, payment_method, amount_paid, transaction_ref } = req.body;
    if (!order_id || !payment_method || !amount_paid) return res.status(400).json({ message: 'Order ID, payment method, and amount paid are required.' });
    try {
        const [result] = await pool.query('INSERT INTO Payments (order_id, payment_method, amount_paid, transaction_ref) VALUES (?, ?, ?, ?)', [order_id, payment_method, amount_paid, transaction_ref]);
        res.status(201).json({ message: 'Payment recorded successfully', paymentId: result.insertId });
    } catch (err) {
        console.error('Error recording payment:', err);
        res.status(500).json({ message: 'Error recording payment', error: err.message });
    }
});

app.put('/api/payments/:id', async (req, res) => {
    const { id } = req.params;
    const { order_id, payment_method, amount_paid, payment_date, transaction_ref } = req.body;
    try {
        const [result] = await pool.query('UPDATE Payments SET order_id = ?, payment_method = ?, amount_paid = ?, payment_date = ?, transaction_ref = ? WHERE payment_id = ?', [order_id, payment_method, amount_paid, payment_date, transaction_ref, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment not found or no changes made' });
        res.json({ message: 'Payment updated successfully' });
    } catch (err) {
        console.error('Error updating payment:', err);
        res.status(500).json({ message: 'Error updating payment', error: err.message });
    }
});

app.delete('/api/payments/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Payments WHERE payment_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment not found' });
        res.json({ message: 'Payment deleted successfully' });
    } catch (err) {
        console.error('Error deleting payment:', err);
        res.status(500).json({ message: 'Error deleting payment', error: err.message });
    }
});

// DailyCashRegister API
app.get('/api/dailycashregisters', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM DailyCashRegister');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching daily cash registers:', err);
        res.status(500).json({ message: 'Error fetching daily cash registers', error: err.message });
    }
});

app.get('/api/dailycashregisters/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM DailyCashRegister WHERE register_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Daily cash register not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching daily cash register:', err);
        res.status(500).json({ message: 'Error fetching daily cash register', error: err.message });
    }
});

app.post('/api/dailycashregisters', async (req, res) => {
    const { user_id, branch_id, open_time, starting_cash } = req.body;
    if (!user_id || !branch_id || !open_time || starting_cash === undefined) {
        return res.status(400).json({ message: 'User ID, Branch ID, open time, and starting cash are required.' });
    }
    try {
        const [result] = await pool.query(
            'INSERT INTO DailyCashRegister (user_id, branch_id, open_time, starting_cash) VALUES (?, ?, ?, ?)',
            [user_id, branch_id, open_time, starting_cash]
        );
        res.status(201).json({ message: 'Daily cash register created successfully', registerId: result.insertId });
    } catch (err) {
        console.error('Error creating daily cash register:', err);
        res.status(500).json({ message: 'Error creating daily cash register', error: err.message });
    }
});

app.put('/api/dailycashregisters/:id', async (req, res) => {
    const { id } = req.params;
    const { close_time, ending_cash, total_sales_cash, total_sales_credit, discrepancy } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE DailyCashRegister SET close_time = ?, ending_cash = ?, total_sales_cash = ?, total_sales_credit = ?, discrepancy = ? WHERE register_id = ?',
            [close_time, ending_cash, total_sales_cash, total_sales_credit, discrepancy, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Daily cash register not found or no changes made' });
        res.json({ message: 'Daily cash register updated successfully' });
    } catch (err) {
        console.error('Error updating daily cash register:', err);
        res.status(500).json({ message: 'Error updating daily cash register', error: err.message });
    }
});

app.delete('/api/dailycashregisters/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM DailyCashRegister WHERE register_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Daily cash register not found' });
        res.json({ message: 'Daily cash register deleted successfully' });
    } catch (err) {
        console.error('Error deleting daily cash register:', err);
        res.status(500).json({ message: 'Error deleting daily cash register', error: err.message });
    }
});


// --- HR Module Tables ---

// Attendance API
app.get('/api/attendance', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Attendance');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching attendance records:', err);
        res.status(500).json({ message: 'Error fetching attendance records', error: err.message });
    }
});

app.get('/api/attendance/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Attendance WHERE attendance_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Attendance record not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching attendance record:', err);
        res.status(500).json({ message: 'Error fetching attendance record', error: err.message });
    }
});

app.post('/api/attendance', async (req, res) => {
    const { employee_id, check_in_time, check_out_time, status } = req.body;
    if (!employee_id || !check_in_time) return res.status(400).json({ message: 'Employee ID and check-in time are required.' });
    try {
        const [result] = await pool.query('INSERT INTO Attendance (employee_id, check_in_time, check_out_time, status) VALUES (?, ?, ?, ?)', [employee_id, check_in_time, check_out_time, status]);
        res.status(201).json({ message: 'Attendance record created successfully', attendanceId: result.insertId });
    } catch (err) {
        console.error('Error creating attendance record:', err);
        res.status(500).json({ message: 'Error creating attendance record', error: err.message });
    }
});

app.put('/api/attendance/:id', async (req, res) => {
    const { id } = req.params;
    const { employee_id, check_in_time, check_out_time, status } = req.body;
    try {
        const [result] = await pool.query('UPDATE Attendance SET employee_id = ?, check_in_time = ?, check_out_time = ?, status = ? WHERE attendance_id = ?', [employee_id, check_in_time, check_out_time, status, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Attendance record not found or no changes made' });
        res.json({ message: 'Attendance record updated successfully' });
    } catch (err) {
        console.error('Error updating attendance record:', err);
        res.status(500).json({ message: 'Error updating attendance record', error: err.message });
    }
});

app.delete('/api/attendance/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Attendance WHERE attendance_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Attendance record not found' });
        res.json({ message: 'Attendance record deleted successfully' });
    } catch (err) {
        console.error('Error deleting attendance record:', err);
        res.status(500).json({ message: 'Error deleting attendance record', error: err.message });
    }
});

// LeaveTypes API
app.get('/api/leavetypes', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM LeaveTypes');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching leave types:', err);
        res.status(500).json({ message: 'Error fetching leave types', error: err.message });
    }
});

app.get('/api/leavetypes/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM LeaveTypes WHERE leave_type_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Leave type not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching leave type:', err);
        res.status(500).json({ message: 'Error fetching leave type', error: err.message });
    }
});

app.post('/api/leavetypes', async (req, res) => {
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

app.put('/api/leavetypes/:id', async (req, res) => {
    const { id } = req.params;
    const { type_name, description } = req.body;
    try {
        const [result] = await pool.query('UPDATE LeaveTypes SET type_name = ?, description = ? WHERE leave_type_id = ?', [type_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Leave type not found or no changes made' });
        res.json({ message: 'Leave type updated successfully' });
    } catch (err) {
        console.error('Error updating leave type:', err);
        res.status(500).json({ message: 'Error updating leave type', error: err.message });
    }
});

app.delete('/api/leavetypes/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM LeaveTypes WHERE leave_type_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Leave type not found' });
        res.json({ message: 'Leave type deleted successfully' });
    } catch (err) {
        console.error('Error deleting leave type:', err);
        res.status(500).json({ message: 'Error deleting leave type', error: err.message });
    }
});

// LeaveRequests API
app.get('/api/leaverequests', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM LeaveRequests');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching leave requests:', err);
        res.status(500).json({ message: 'Error fetching leave requests', error: err.message });
    }
});

app.get('/api/leaverequests/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM LeaveRequests WHERE leave_request_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Leave request not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching leave request:', err);
        res.status(500).json({ message: 'Error fetching leave request', error: err.message });
    }
});

app.post('/api/leaverequests', async (req, res) => {
    const { employee_id, leave_type_id, start_date, end_date, number_of_days, reason, status, approved_by_user_id } = req.body;
    if (!employee_id || !leave_type_id || !start_date || !end_date || !number_of_days) {
        return res.status(400).json({ message: 'Employee ID, leave type, start/end dates, and number of days are required.' });
    }
    try {
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

app.put('/api/leaverequests/:id', async (req, res) => {
    const { id } = req.params;
    const { employee_id, leave_type_id, start_date, end_date, number_of_days, reason, status, approved_by_user_id, approval_date } = req.body;
    try {
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

app.delete('/api/leaverequests/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE LeaveRequests SET status = "Canceled" WHERE leave_request_id = ?', [id]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Leave request not found' });
        res.json({ message: 'Leave request cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling leave request:', err);
        res.status(500).json({ message: 'Error cancelling leave request', error: err.message });
    }
});

// Payrolls API
app.get('/api/payrolls', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Payrolls');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payrolls:', err);
        res.status(500).json({ message: 'Error fetching payrolls', error: err.message });
    }
});

app.get('/api/payrolls/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Payrolls WHERE payroll_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Payroll not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payroll:', err);
        res.status(500).json({ message: 'Error fetching payroll', error: err.message });
    }
});

app.post('/api/payrolls', async (req, res) => {
    const { employee_id, payroll_period_start, payroll_period_end, gross_salary, deductions, net_salary, payment_date } = req.body;
    if (!employee_id || !payroll_period_start || !payroll_period_end || !gross_salary || !net_salary || !payment_date) {
        return res.status(400).json({ message: 'Employee ID, payroll period, gross/net salary, and payment date are required.' });
    }
    try {
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

app.put('/api/payrolls/:id', async (req, res) => {
    const { id } = req.params;
    const { employee_id, payroll_period_start, payroll_period_end, gross_salary, deductions, net_salary, payment_date } = req.body;
    try {
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

app.delete('/api/payrolls/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Payrolls WHERE payroll_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payroll not found' });
        res.json({ message: 'Payroll deleted successfully' });
    } catch (err) {
        console.error('Error deleting payroll:', err);
        res.status(500).json({ message: 'Error deleting payroll', error: err.message });
    }
});

// Benefits API
app.get('/api/benefits', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Benefits');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching benefits:', err);
        res.status(500).json({ message: 'Error fetching benefits', error: err.message });
    }
});

app.get('/api/benefits/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Benefits WHERE benefit_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Benefit not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching benefit:', err);
        res.status(500).json({ message: 'Error fetching benefit', error: err.message });
    }
});

app.post('/api/benefits', async (req, res) => {
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

app.put('/api/benefits/:id', async (req, res) => {
    const { id } = req.params;
    const { benefit_name, description } = req.body;
    try {
        const [result] = await pool.query('UPDATE Benefits SET benefit_name = ?, description = ? WHERE benefit_id = ?', [benefit_name, description, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Benefit not found or no changes made' });
        res.json({ message: 'Benefit updated successfully' });
    } catch (err) {
        console.error('Error updating benefit:', err);
        res.status(500).json({ message: 'Error updating benefit', error: err.message });
    }
});

app.delete('/api/benefits/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Benefits WHERE benefit_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Benefit not found' });
        res.json({ message: 'Benefit deleted successfully' });
    } catch (err) {
        console.error('Error deleting benefit:', err);
        res.status(500).json({ message: 'Error deleting benefit', error: err.message });
    }
});

// EmployeeBenefits API (Many-to-Many relationship)
app.get('/api/employeebenefits', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT eb.employee_benefit_id, eb.employee_id, e.first_name, e.last_name, eb.benefit_id, b.benefit_name, eb.effective_date, eb.end_date FROM EmployeeBenefits eb JOIN Employees e ON eb.employee_id = e.employee_id JOIN Benefits b ON eb.benefit_id = b.benefit_id');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching employee benefits:', err);
        res.status(500).json({ message: 'Error fetching employee benefits', error: err.message });
    }
});

app.get('/api/employeebenefits/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM EmployeeBenefits WHERE employee_benefit_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Employee benefit not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching employee benefit:', err);
        res.status(500).json({ message: 'Error fetching employee benefit', error: err.message });
    }
});

app.post('/api/employeebenefits', async (req, res) => {
    const { employee_id, benefit_id, effective_date, end_date } = req.body;
    if (!employee_id || !benefit_id || !effective_date) return res.status(400).json({ message: 'Employee ID, benefit ID, and effective date are required.' });
    try {
        const [result] = await pool.query('INSERT INTO EmployeeBenefits (employee_id, benefit_id, effective_date, end_date) VALUES (?, ?, ?, ?)', [employee_id, benefit_id, effective_date, end_date]);
        res.status(201).json({ message: 'Employee benefit assigned successfully', employeeBenefitId: result.insertId });
    } catch (err) {
        console.error('Error assigning employee benefit:', err);
        res.status(500).json({ message: 'Error assigning employee benefit', error: err.message });
    }
});

app.put('/api/employeebenefits/:id', async (req, res) => {
    const { id } = req.params;
    const { employee_id, benefit_id, effective_date, end_date } = req.body;
    try {
        const [result] = await pool.query('UPDATE EmployeeBenefits SET employee_id = ?, benefit_id = ?, effective_date = ?, end_date = ? WHERE employee_benefit_id = ?', [employee_id, benefit_id, effective_date, end_date, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee benefit not found or no changes made' });
        res.json({ message: 'Employee benefit updated successfully' });
    } catch (err) {
        console.error('Error updating employee benefit:', err);
        res.status(500).json({ message: 'Error updating employee benefit', error: err.message });
    }
});

app.delete('/api/employeebenefits/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM EmployeeBenefits WHERE employee_benefit_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Employee benefit not found' });
        res.json({ message: 'Employee benefit deleted successfully' });
    } catch (err) {
        console.error('Error deleting employee benefit:', err);
        res.status(500).json({ message: 'Error deleting employee benefit', error: err.message });
    }
});

// PerformanceReviews API
app.get('/api/performancereviews', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM PerformanceReviews');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching performance reviews:', err);
        res.status(500).json({ message: 'Error fetching performance reviews', error: err.message });
    }
});

app.get('/api/performancereviews/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM PerformanceReviews WHERE review_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Performance review not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching performance review:', err);
        res.status(500).json({ message: 'Error fetching performance review', error: err.message });
    }
});

app.post('/api/performancereviews', async (req, res) => {
    const { employee_id, reviewer_id, review_date, rating, comments } = req.body;
    if (!employee_id || !reviewer_id || !review_date) return res.status(400).json({ message: 'Employee ID, reviewer ID, and review date are required.' });
    try {
        const [result] = await pool.query('INSERT INTO PerformanceReviews (employee_id, reviewer_id, review_date, rating, comments) VALUES (?, ?, ?, ?, ?)', [employee_id, reviewer_id, review_date, rating, comments]);
        res.status(201).json({ message: 'Performance review created successfully', reviewId: result.insertId });
    } catch (err) {
        console.error('Error creating performance review:', err);
        res.status(500).json({ message: 'Error creating performance review', error: err.message });
    }
});

app.put('/api/performancereviews/:id', async (req, res) => {
    const { id } = req.params;
    const { employee_id, reviewer_id, review_date, rating, comments } = req.body;
    try {
        const [result] = await pool.query('UPDATE PerformanceReviews SET employee_id = ?, reviewer_id = ?, review_date = ?, rating = ?, comments = ? WHERE review_id = ?', [employee_id, reviewer_id, review_date, rating, comments, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Performance review not found or no changes made' });
        res.json({ message: 'Performance review updated successfully' });
    } catch (err) {
        console.error('Error updating performance review:', err);
        res.status(500).json({ message: 'Error updating performance review', error: err.message });
    }
});

app.delete('/api/performancereviews/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM PerformanceReviews WHERE review_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Performance review not found' });
        res.json({ message: 'Performance review deleted successfully' });
    } catch (err) {
        console.error('Error deleting performance review:', err);
        res.status(500).json({ message: 'Error deleting performance review', error: err.message });
    }
});


// --- ERP Module Tables (Inventory & Purchasing) ---

// Suppliers API (already defined above)
// (GET all, GET by ID, POST, PUT, DELETE - already provided in previous version)

// Warehouses API
app.get('/api/warehouses', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Warehouses');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching warehouses:', err);
        res.status(500).json({ message: 'Error fetching warehouses', error: err.message });
    }
});

app.get('/api/warehouses/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Warehouses WHERE warehouse_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Warehouse not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching warehouse:', err);
        res.status(500).json({ message: 'Error fetching warehouse', error: err.message });
    }
});

app.post('/api/warehouses', async (req, res) => {
    const { warehouse_name, address, branch_id } = req.body;
    if (!warehouse_name) return res.status(400).json({ message: 'Warehouse name is required.' });
    try {
        const [result] = await pool.query('INSERT INTO Warehouses (warehouse_name, address, branch_id) VALUES (?, ?, ?)', [warehouse_name, address, branch_id]);
        res.status(201).json({ message: 'Warehouse created successfully', warehouseId: result.insertId });
    } catch (err) {
        console.error('Error creating warehouse:', err);
        res.status(500).json({ message: 'Error creating warehouse', error: err.message });
    }
});

app.put('/api/warehouses/:id', async (req, res) => {
    const { id } = req.params;
    const { warehouse_name, address, branch_id } = req.body;
    try {
        const [result] = await pool.query('UPDATE Warehouses SET warehouse_name = ?, address = ?, branch_id = ? WHERE warehouse_id = ?', [warehouse_name, address, branch_id, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Warehouse not found or no changes made' });
        res.json({ message: 'Warehouse updated successfully' });
    } catch (err) {
        console.error('Error updating warehouse:', err);
        res.status(500).json({ message: 'Error updating warehouse', error: err.message });
    }
});

app.delete('/api/warehouses/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM Warehouses WHERE warehouse_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Warehouse not found' });
        res.json({ message: 'Warehouse deleted successfully' });
    } catch (err) {
        console.error('Error deleting warehouse:', err);
        res.status(500).json({ message: 'Error deleting warehouse', error: err.message });
    }
});

// InventoryLevels API
app.get('/api/inventorylevels', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM InventoryLevels');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching inventory levels:', err);
        res.status(500).json({ message: 'Error fetching inventory levels', error: err.message });
    }
});

app.get('/api/inventorylevels/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM InventoryLevels WHERE inventory_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Inventory level not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching inventory level:', err);
        res.status(500).json({ message: 'Error fetching inventory level', error: err.message });
    }
});

app.post('/api/inventorylevels', async (req, res) => {
    const { product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point } = req.body;
    if (!product_id || !warehouse_id || quantity_on_hand === undefined) return res.status(400).json({ message: 'Product ID, warehouse ID, and quantity on hand are required.' });
    try {
        const [result] = await pool.query('INSERT INTO InventoryLevels (product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point) VALUES (?, ?, ?, ?, ?)', [product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point]);
        res.status(201).json({ message: 'Inventory level created successfully', inventoryId: result.insertId });
    } catch (err) {
        console.error('Error creating inventory level:', err);
        res.status(500).json({ message: 'Error creating inventory level', error: err.message });
    }
});

app.put('/api/inventorylevels/:id', async (req, res) => {
    const { id } = req.params;
    const { product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point } = req.body;
    try {
        const [result] = await pool.query('UPDATE InventoryLevels SET product_id = ?, warehouse_id = ?, quantity_on_hand = ?, min_stock_level = ?, reorder_point = ? WHERE inventory_id = ?', [product_id, warehouse_id, quantity_on_hand, min_stock_level, reorder_point, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Inventory level not found or no changes made' });
        res.json({ message: 'Inventory level updated successfully' });
    } catch (err) {
        console.error('Error updating inventory level:', err);
        res.status(500).json({ message: 'Error updating inventory level', error: err.message });
    }
});

app.delete('/api/inventorylevels/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM InventoryLevels WHERE inventory_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Inventory level not found' });
        res.json({ message: 'Inventory level deleted successfully' });
    } catch (err) {
        console.error('Error deleting inventory level:', err);
        res.status(500).json({ message: 'Error deleting inventory level', error: err.message });
    }
});

// PurchaseOrders API
app.get('/api/purchaseorders', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM PurchaseOrders');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching purchase orders:', err);
        res.status(500).json({ message: 'Error fetching purchase orders', error: err.message });
    }
});

app.get('/api/purchaseorders/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM PurchaseOrders WHERE po_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Purchase order not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching purchase order:', err);
        res.status(500).json({ message: 'Error fetching purchase order', error: err.message });
    }
});

app.post('/api/purchaseorders', async (req, res) => {
    const { supplier_id, order_date, delivery_date, total_amount, status, user_id, items } = req.body;
    if (!supplier_id || !order_date || !total_amount || !user_id || !items || items.length === 0) {
        return res.status(400).json({ message: 'Supplier ID, order date, total amount, user ID, and at least one item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [poResult] = await connection.query(
            'INSERT INTO PurchaseOrders (supplier_id, order_date, delivery_date, total_amount, status, user_id) VALUES (?, ?, ?, ?, ?, ?)',
            [supplier_id, order_date, delivery_date, total_amount, status, user_id]
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

app.put('/api/purchaseorders/:id', async (req, res) => {
    const { id } = req.params;
    const { supplier_id, order_date, delivery_date, total_amount, status, user_id } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE PurchaseOrders SET supplier_id = ?, order_date = ?, delivery_date = ?, total_amount = ?, status = ?, user_id = ? WHERE po_id = ?',
            [supplier_id, order_date, delivery_date, total_amount, status, user_id, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Purchase order not found or no changes made' });
        res.json({ message: 'Purchase order updated successfully' });
    } catch (err) {
        console.error('Error updating purchase order:', err);
        res.status(500).json({ message: 'Error updating purchase order', error: err.message });
    }
});

app.delete('/api/purchaseorders/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE PurchaseOrders SET status = "Cancelled" WHERE po_id = ?', [id]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Purchase order not found' });
        res.json({ message: 'Purchase order cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling purchase order:', err);
        res.status(500).json({ message: 'Error cancelling purchase order', error: err.message });
    }
});

// PurchaseOrderItems API (Typically managed via PurchaseOrders)
app.get('/api/purchaseorderitems', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM PurchaseOrderItems');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching purchase order items:', err);
        res.status(500).json({ message: 'Error fetching purchase order items', error: err.message });
    }
});

app.get('/api/purchaseorderitems/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM PurchaseOrderItems WHERE po_item_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Purchase order item not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching purchase order item:', err);
        res.status(500).json({ message: 'Error fetching purchase order item', error: err.message });
    }
});

// GoodsReceipts API
app.get('/api/goodsreceipts', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM GoodsReceipts');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching goods receipts:', err);
        res.status(500).json({ message: 'Error fetching goods receipts', error: err.message });
    }
});

app.get('/api/goodsreceipts/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM GoodsReceipts WHERE gr_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Goods receipt not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching goods receipt:', err);
        res.status(500).json({ message: 'Error fetching goods receipt', error: err.message });
    }
});

app.post('/api/goodsreceipts', async (req, res) => {
    const { po_id, warehouse_id, user_id, items } = req.body;
    if (!warehouse_id || !user_id || !items || items.length === 0) {
        return res.status(400).json({ message: 'Warehouse ID, user ID, and at least one item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [grResult] = await connection.query(
            'INSERT INTO GoodsReceipts (po_id, warehouse_id, user_id) VALUES (?, ?, ?)',
            [po_id, warehouse_id, user_id]
        );
        const grId = grResult.insertId;

        for (const item of items) {
            await connection.query(
                'INSERT INTO GoodsReceiptItems (gr_id, product_id, quantity_received) VALUES (?, ?, ?)',
                [grId, item.product_id, item.quantity_received]
            );
            // Update InventoryLevels and log InventoryTransactions
            await connection.query(
                'INSERT INTO InventoryTransactions (product_id, warehouse_id, transaction_type, quantity_change, reference_doc_type, reference_doc_id, user_id, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [item.product_id, warehouse_id, 'Purchase', item.quantity_received, 'GoodsReceipt', grId, user_id, `Goods Receipt for GR ${grId}`]
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

app.put('/api/goodsreceipts/:id', async (req, res) => {
    const { id } = req.params;
    const { po_id, warehouse_id, receipt_date, user_id } = req.body;
    try {
        const [result] = await pool.query('UPDATE GoodsReceipts SET po_id = ?, warehouse_id = ?, receipt_date = ?, user_id = ? WHERE gr_id = ?', [po_id, warehouse_id, receipt_date, user_id, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Goods receipt not found or no changes made' });
        res.json({ message: 'Goods receipt updated successfully' });
    } catch (err) {
        console.error('Error updating goods receipt:', err);
        res.status(500).json({ message: 'Error updating goods receipt', error: err.message });
    }
});

app.delete('/api/goodsreceipts/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM GoodsReceipts WHERE gr_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Goods receipt not found' });
        res.json({ message: 'Goods receipt deleted successfully' });
    } catch (err) {
        console.error('Error deleting goods receipt:', err);
        res.status(500).json({ message: 'Error deleting goods receipt', error: err.message });
    }
});

// GoodsReceiptItems API (Typically managed via GoodsReceipts)
app.get('/api/goodsreceiptitems', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM GoodsReceiptItems');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching goods receipt items:', err);
        res.status(500).json({ message: 'Error fetching goods receipt items', error: err.message });
    }
});

app.get('/api/goodsreceiptitems/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM GoodsReceiptItems WHERE gr_item_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Goods receipt item not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching goods receipt item:', err);
        res.status(500).json({ message: 'Error fetching goods receipt item', error: err.message });
    }
});

// InventoryTransactions API (Read-only, typically generated by other modules)
app.get('/api/inventorytransactions', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM InventoryTransactions ORDER BY transaction_date DESC');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching inventory transactions:', err);
        res.status(500).json({ message: 'Error fetching inventory transactions', error: err.message });
    }
});

app.get('/api/inventorytransactions/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM InventoryTransactions WHERE transaction_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Inventory transaction not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching inventory transaction:', err);
        res.status(500).json({ message: 'Error fetching inventory transaction', error: err.message });
    }
});


// --- ERP Module Tables (Financial Management) ---

// ChartOfAccounts API
app.get('/api/chartofaccounts', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM ChartOfAccounts');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching chart of accounts:', err);
        res.status(500).json({ message: 'Error fetching chart of accounts', error: err.message });
    }
});

app.get('/api/chartofaccounts/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM ChartOfAccounts WHERE account_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Account not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching account:', err);
        res.status(500).json({ message: 'Error fetching account', error: err.message });
    }
});

app.post('/api/chartofaccounts', async (req, res) => {
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

app.put('/api/chartofaccounts/:id', async (req, res) => {
    const { id } = req.params;
    const { account_code, account_name, account_type, parent_account_id, is_active } = req.body;
    try {
        const [result] = await pool.query('UPDATE ChartOfAccounts SET account_code = ?, account_name = ?, account_type = ?, parent_account_id = ?, is_active = ? WHERE account_id = ?', [account_code, account_name, account_type, parent_account_id, is_active, id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Account not found or no changes made' });
        res.json({ message: 'Account updated successfully' });
    } catch (err) {
        console.error('Error updating account:', err);
        res.status(500).json({ message: 'Error updating account', error: err.message });
    }
});

app.delete('/api/chartofaccounts/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE ChartOfAccounts SET is_active = FALSE WHERE account_id = ?', [id]); // Soft delete
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Account not found' });
        res.json({ message: 'Account deactivated successfully' });
    } catch (err) {
        console.error('Error deactivating account:', err);
        res.status(500).json({ message: 'Error deactivating account', error: err.message });
    }
});

// JournalEntries API
app.get('/api/journalentries', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM JournalEntries ORDER BY entry_date DESC');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching journal entries:', err);
        res.status(500).json({ message: 'Error fetching journal entries', error: err.message });
    }
});

app.get('/api/journalentries/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM JournalEntries WHERE entry_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Journal entry not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching journal entry:', err);
        res.status(500).json({ message: 'Error fetching journal entry', error: err.message });
    }
});

app.post('/api/journalentries', async (req, res) => {
    const { entry_date, description, reference_type, reference_id, user_id, lines } = req.body;
    if (!entry_date || !user_id || !lines || lines.length === 0) {
        return res.status(400).json({ message: 'Entry date, user ID, and at least one line item are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        const [entryResult] = await connection.query(
            'INSERT INTO JournalEntries (entry_date, description, reference_type, reference_id, user_id) VALUES (?, ?, ?, ?, ?)',
            [entry_date, description, reference_type, reference_id, user_id]
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

app.put('/api/journalentries/:id', async (req, res) => {
    const { id } = req.params;
    const { entry_date, description, reference_type, reference_id, user_id } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE JournalEntries SET entry_date = ?, description = ?, reference_type = ?, reference_id = ?, user_id = ? WHERE entry_id = ?',
            [entry_date, description, reference_type, reference_id, user_id, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Journal entry not found or no changes made' });
        res.json({ message: 'Journal entry updated successfully' });
    } catch (err) {
        console.error('Error updating journal entry:', err);
        res.status(500).json({ message: 'Error updating journal entry', error: err.message });
    }
});

app.delete('/api/journalentries/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM JournalEntries WHERE entry_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Journal entry not found' });
        res.json({ message: 'Journal entry deleted successfully' });
    } catch (err) {
        console.error('Error deleting journal entry:', err);
        res.status(500).json({ message: 'Error deleting journal entry', error: err.message });
    }
});

// JournalEntryLines API (Typically managed via JournalEntries)
app.get('/api/journalentrylines', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM JournalEntryLines');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching journal entry lines:', err);
        res.status(500).json({ message: 'Error fetching journal entry lines', error: err.message });
    }
});

app.get('/api/journalentrylines/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM JournalEntryLines WHERE line_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Journal entry line not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching journal entry line:', err);
        res.status(500).json({ message: 'Error fetching journal entry line', error: err.message });
    }
});

// Invoices API
app.get('/api/invoices', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM Invoices');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching invoices:', err);
        res.status(500).json({ message: 'Error fetching invoices', error: err.message });
    }
});

app.get('/api/invoices/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM Invoices WHERE invoice_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Invoice not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching invoice:', err);
        res.status(500).json({ message: 'Error fetching invoice', error: err.message });
    }
});

app.post('/api/invoices', async (req, res) => {
    const { invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id } = req.body;
    if (!invoice_date || !total_amount || (!customer_id && !supplier_id)) {
        return res.status(400).json({ message: 'Invoice date, total amount, and either customer ID or supplier ID are required.' });
    }
    try {
        const [result] = await pool.query(
            'INSERT INTO Invoices (invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id]
        );
        res.status(201).json({ message: 'Invoice created successfully', invoiceId: result.insertId });
    } catch (err) {
        console.error('Error creating invoice:', err);
        res.status(500).json({ message: 'Error creating invoice', error: err.message });
    }
});

app.put('/api/invoices/:id', async (req, res) => {
    const { id } = req.params;
    const { invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE Invoices SET invoice_date = ?, due_date = ?, customer_id = ?, supplier_id = ?, total_amount = ?, status = ?, reference_order_id = ? WHERE invoice_id = ?',
            [invoice_date, due_date, customer_id, supplier_id, total_amount, status, reference_order_id, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Invoice not found or no changes made' });
        res.json({ message: 'Invoice updated successfully' });
    } catch (err) {
        console.error('Error updating invoice:', err);
        res.status(500).json({ message: 'Error updating invoice', error: err.message });
    }
});

app.delete('/api/invoices/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('UPDATE Invoices SET status = "Cancelled" WHERE invoice_id = ?', [id]); // Soft delete/cancel
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Invoice not found' });
        res.json({ message: 'Invoice cancelled successfully' });
    } catch (err) {
        console.error('Error cancelling invoice:', err);
        res.status(500).json({ message: 'Error cancelling invoice', error: err.message });
    }
});

// PaymentsReceived API
app.get('/api/paymentsreceived', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM PaymentsReceived');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payments received:', err);
        res.status(500).json({ message: 'Error fetching payments received', error: err.message });
    }
});

app.get('/api/paymentsreceived/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM PaymentsReceived WHERE receipt_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Payment received not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payment received:', err);
        res.status(500).json({ message: 'Error fetching payment received', error: err.message });
    }
});

app.post('/api/paymentsreceived', async (req, res) => {
    const { invoice_id, amount_received, payment_method, user_id } = req.body;
    if (!invoice_id || !amount_received || !payment_method) {
        return res.status(400).json({ message: 'Invoice ID, amount received, and payment method are required.' });
    }
    try {
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

app.put('/api/paymentsreceived/:id', async (req, res) => {
    const { id } = req.params;
    const { invoice_id, amount_received, receipt_date, payment_method, user_id } = req.body;
    try {
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

app.delete('/api/paymentsreceived/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM PaymentsReceived WHERE receipt_id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ message: 'Payment received not found' });
        res.json({ message: 'Payment received deleted successfully' });
    } catch (err) {
        console.error('Error deleting payment received:', err);
        res.status(500).json({ message: 'Error deleting payment received', error: err.message });
    }
});

// PaymentsMade API
app.get('/api/paymentsmade', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM PaymentsMade');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching payments made:', err);
        res.status(500).json({ message: 'Error fetching payments made', error: err.message });
    }
});

app.get('/api/paymentsmade/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [rows] = await pool.query('SELECT * FROM PaymentsMade WHERE payment_id = ?', [id]);
        if (rows.length === 0) return res.status(404).json({ message: 'Payment made not found' });
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching payment made:', err);
        res.status(500).json({ message: 'Error fetching payment made', error: err.message });
    }
});

app.post('/api/paymentsmade', async (req, res) => {
    const { invoice_id, amount_paid, payment_method, user_id } = req.body;
    if (!invoice_id || !amount_paid || !payment_method) {
        return res.status(400).json({ message: 'Invoice ID, amount paid, and payment method are required.' });
    }
    try {
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

app.put('/api/paymentsmade/:id', async (req, res) => {
    const { id } = req.params;
    const { invoice_id, amount_paid, payment_date, payment_method, user_id } = req.body;
    try {
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

app.delete('/api/paymentsmade/:id', async (req, res) => {
    const { id } = req.params;
    try {
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