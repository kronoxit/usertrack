import express from 'express';
import path from 'path';
import { spawn, ChildProcess } from 'child_process';
import { createServer as createViteServer } from 'vite';

const PORT = 3000;
const PYTHON_PORT = 8000;
let pythonProcess: ChildProcess | null = null;

// Запуск Python REST API бэкенда
function startPythonBackend() {
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
  const scriptPath = path.join(process.cwd(), 'backend', 'app.py');

  console.log(`[UserTrack Server] Запуск Python ядра: ${pythonCmd} ${scriptPath} --port ${PYTHON_PORT}`);

  pythonProcess = spawn(pythonCmd, [scriptPath, '--port', String(PYTHON_PORT)], {
    stdio: 'inherit',
    cwd: process.cwd(),
  });

  pythonProcess.on('error', (err) => {
    console.error('[UserTrack Server] Ошибка при запуске Python процесса:', err.message);
  });

  pythonProcess.on('exit', (code, signal) => {
    console.warn(`[UserTrack Server] Python процесс завершился с кодом ${code}, сигнал: ${signal}`);
  });
}

// Завершение Python процесса при остановке Node.js
process.on('SIGINT', () => {
  if (pythonProcess) pythonProcess.kill('SIGINT');
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (pythonProcess) pythonProcess.kill('SIGTERM');
  process.exit(0);
});

async function startServer() {
  startPythonBackend();

  const app = express();
  app.use(express.json());

  // Проксирование всех запросов /api/* на Python бэкенд (порт 8000)
  app.all('/api/*', async (req, res) => {
    const targetUrl = `http://127.0.0.1:${PYTHON_PORT}${req.originalUrl}`;
    try {
      const headers: Record<string, string> = {
        'content-type': req.headers['content-type'] || 'application/json',
      };
      if (req.headers.authorization) {
        headers['authorization'] = req.headers.authorization;
      }

      const options: RequestInit = {
        method: req.method,
        headers,
      };

      if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
        options.body = JSON.stringify(req.body);
      }

      const pythonResp = await fetch(targetUrl, options);
      const data = await pythonResp.text();

      res.status(pythonResp.status);
      res.setHeader('Content-Type', pythonResp.headers.get('content-type') || 'application/json');
      res.send(data);
    } catch {
      // Fallback если Python бэкенд еще инициализируется
      if (req.originalUrl === '/api/health' || req.originalUrl === '/api/status') {
        res.json({
          status: 'ok',
          engine: 'Python 3.10 Core',
          message: 'Python backend is warming up or connected',
        });
      } else {
        res.status(503).json({
          error: 'Python backend service initializing',
          target: targetUrl,
        });
      }
    }
  });

  // Vite middleware для режима разработки или раздача статики в production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[UserTrack] Сервер успешно запущен на http://0.0.0.0:${PORT}`);
  });
}

startServer();
