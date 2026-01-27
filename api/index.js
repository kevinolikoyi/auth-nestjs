let cachedApp = null;

module.exports = async function handler(req, res) {
  try {
    if (!cachedApp) {
      const { createApp } = await import('../dist/src/app.factory.js');
      cachedApp = await createApp();
    }

    // Sur Vercel, une function dans /api reçoit l’URL SANS le préfixe "/api".
    // Or notre app NestJS a `setGlobalPrefix('api')`, donc elle attend des chemins "/api/...".
    // Exemple: GET /api/docs -> ici req.url === "/docs" ; on la transforme en "/api/docs".
    if (typeof req.url === 'string' && !req.url.startsWith('/api')) {
      req.url = `/api${req.url === '/' ? '' : req.url}`;
    }
    
    return cachedApp(req, res);
  } catch (error) {
    console.error('Error in Vercel handler:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
};