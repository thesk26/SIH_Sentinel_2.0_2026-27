const path = require('node:path');
const { app, BrowserWindow, dialog } = require('electron');

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  let server;

  app.on('second-instance', () => {
    const window = BrowserWindow.getAllWindows()[0];
    if (window) {
      if (window.isMinimized()) window.restore();
      window.focus();
    }
  });

  app.whenReady().then(async () => {
    process.env.NODE_ENV = 'production';
    process.env.SENTINEL_DESKTOP = 'true';
    process.env.SENTINEL_APP_ROOT = app.getAppPath();
    process.env.SENTINEL_DATA_DIR = path.join(app.getPath('userData'), 'data');
    process.env.HOST = '127.0.0.1';
    process.env.PORT = '0';

    try {
      const { startServer } = require('../dist/server.cjs');
      server = await startServer({ host: process.env.HOST, port: 0 });
      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('The local SENTINEL server did not provide a network address.');
      }

      const window = new BrowserWindow({
        width: 1440,
        height: 960,
        minWidth: 1024,
        minHeight: 720,
        webPreferences: {
          contextIsolation: true,
          nodeIntegration: false,
          sandbox: true
        }
      });

      await window.loadURL(`http://127.0.0.1:${address.port}`);
    } catch (error) {
      dialog.showErrorBox(
        'SENTINEL could not start',
        error instanceof Error ? error.message : String(error)
      );
      app.quit();
    }
  });

  app.on('before-quit', () => {
    if (server) server.close();
  });

  app.on('window-all-closed', () => app.quit());
}
