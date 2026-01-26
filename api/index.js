let cachedApp = null;

module.exports = async function handler(req, res) {
  try {
    if (!cachedApp) {
      const { createApp } = await import('../dist/src/app.factory.js');
      cachedApp = await createApp();
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