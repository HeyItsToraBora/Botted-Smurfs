const { getDB } = require('./db');

function dashboardHandler(req, res) {
    const db = getDB();

    db.get('SELECT email FROM users WHERE email = ?', [req.user.email], (err, row) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (!row) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.json({
            success: true,
            message: 'Dashboard data retrieved successfully',
            data: {
                email: row.email
            }
        });
    });
}

module.exports = {
    dashboardHandler
}; 