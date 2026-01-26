import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'jwtsecret';

export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export function requireDM(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user || req.user.role !== 'DM') {
      return res
        .status(403)
        .json({ error: 'Forbidden: DM role required' });
    }
    next();
  });
}
