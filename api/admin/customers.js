import { Pool } from 'pg';
import jwt from 'jsonwebtoken';

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

export default async function handler(req, res) {
    if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

    const cookies = req.headers.cookie || '';
    const tokenCookie = cookies.split('; ').find(row => row.startsWith('nexus_token='));

    if (!tokenCookie) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const token = tokenCookie.split('=')[1];
        const decoded = jwt.verify(token, process.env.AUTH_SECRET);

        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: Admin access required' });
        }

        const client = await pool.connect();
        const result = await client.query('SELECT user_id, full_name, mobile_number, email, role, status, created_at FROM customers ORDER BY created_at DESC');
        client.release();

        return res.status(200).json({ success: true, customers: result.rows });
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired session' });
    }
}
