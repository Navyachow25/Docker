import express from 'express';
import bcrypt   from 'bcrypt';
import jwt      from 'jsonwebtoken';

const router  = express.Router();
const USERS   = new Map();                  // replace with Mongo later
const SECRET  = process.env.JWT_SECRET || 'super‑secret‑key';
const OPTIONS = { expiresIn: '2h' };

/* POST /api/auth/signup { email, password } */
router.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (USERS.has(email)) return res.status(409).json({ msg: 'User exists' });
  USERS.set(email, await bcrypt.hash(password, 10));
  res.json({ msg: 'Account created' });
});

/* POST /api/auth/login { email, password } */
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const hash = USERS.get(email);
  if (!hash || !(await bcrypt.compare(password, hash)))
    return res.status(401).json({ msg: 'Invalid credentials' });

  const token = jwt.sign({ email }, SECRET, OPTIONS);
  res.json({ token });
});

/* middleware: protect routes that need a valid user */
export function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ msg: 'Auth required' });
  }
}

export default router;
