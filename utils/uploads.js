import path from 'path';

export const UPLOADS_PATH =
  process.env.UPLOADS_PATH || path.resolve('.', 'uploads');
