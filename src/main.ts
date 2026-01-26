import 'dotenv/config';
import { createApp } from './app.factory';

async function bootstrap() {
  const expressApp = await createApp();
  const port = process.env.PORT ?? 3000;
  await new Promise<void>((resolve) =>
    expressApp.listen(port, () => resolve()),
  );

  console.log(`🚀 Application running on: http://localhost:${port}`);
  console.log(`📚 Swagger documentation: http://localhost:${port}/api/docs`);
}
void bootstrap();
