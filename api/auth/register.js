import { Pool } from 'pg';
import bcrypt from 'bcryptjs';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { fullName, mobileNumber, email, password } = req.body;
    if (!fullName || !mobileNumber || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const client = await pool.connect();
        const existing = await client.query('SELECT id FROM customers WHERE email = $1', [email.toLowerCase()]);

        if (existing.rows.length > 0) {
            client.release();
            return res.status(409).json({ error: 'An account with this email already exists. Please sign in instead.' });
        }

        const salt = await bcrypt.genSalt(12);
        const passwordHash = await bcrypt.hash(password, salt);
        const userId = 'usr-' + Math.random().toString(36).substr(2, 9);

        const result = await client.query(
            `INSERT INTO customers (user_id, full_name, mobile_number, email, password_hash, role, status) 
             VALUES ($1, $2, $3, $4, $5, 'customer', 'Active') RETURNING user_id, full_name, email, role, created_at`,
            [userId, fullName, mobileNumber, email.toLowerCase(), passwordHash]
        );

        client.release();
        return res.status(201).json({ success: true, user: result.rows[0] });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
}
