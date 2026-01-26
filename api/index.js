let cached = null;

module.exports = async (req, res) => {
  if (!cached) {
    const { createApp } = await import('../dist/app.factory.js');
    cached = await createApp();
  }
    return cached(req, res);
  }