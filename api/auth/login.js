import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Invalid email or password.' });

    try {
        const client = await pool.connect();
        const result = await client.query('SELECT * FROM customers WHERE email = $1', [email.toLowerCase()]);
        client.release();

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const token = jwt.sign(
            { userId: user.user_id, email: user.email, role: user.role, fullName: user.full_name },
            process.env.AUTH_SECRET,
            { expiresIn: '7d' }
        );

        res.setHeader('Set-Cookie', `nexus_token=${token}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=${7 * 24 * 60 * 60}`);
        return res.status(200).json({ success: true, user: { userId: user.user_id, fullName: user.full_name, email: user.email, role: user.role, mobileNumber: user.mobile_number } });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error.' });
    }
}
