// Catch-all Vercel function: /api/* -> NestJS
let cachedApp = null;

module.exports = async function handler(req, res) {
  try {
    if (!cachedApp) {
      const { createApp } = await import('../dist/src/app.factory.js');
      cachedApp = await createApp();
    }

    // Sur Vercel, /api/* arrive ici avec req.url sans le préfixe "/api"
    // Exemple: GET /api/docs -> req.url === "/docs"
    // Notre NestJS a setGlobalPrefix('api'), donc on remet "/api" devant.
    if (typeof req.url === 'string' && !req.url.startsWith('/api')) {
      req.url = `/api${req.url === '/' ? '' : req.url}`;
    }

    return cachedApp(req, res);
  } catch (error) {
    console.error('Error in Vercel handler:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error?.message ?? String(error),
    });
  }
};

