#!/usr/bin/env node

/**
 * CTI Agentic Defense System - Global CLI Launcher & Interactive Controller
 * Ho tro khoi chay qua npm: cti-defense hoac cti
 * Chuan Interactive Controller giu terminal chay lien tuc (tuong tu 9router)
 */

const { spawn, execSync } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');

const ROOT_DIR = path.resolve(__dirname, '..');
const SANDBOX_DIR = path.join(ROOT_DIR, 'khang_sandbox_full_cti');
const APP_FILE = path.join(SANDBOX_DIR, 'live_dashboard_app.py');
const SYSTEM_CTL_FILE = path.join(SANDBOX_DIR, 'system_ctl.py');
const PORT = 8765;
const WAF_PORT = 8766;

function openBrowser(url) {
  const platform = process.platform;
  try {
    if (platform === 'win32') {
      execSync(`start "" "${url}"`, { stdio: 'ignore' });
    } else if (platform === 'darwin') {
      execSync(`open "${url}"`, { stdio: 'ignore' });
    } else {
      execSync(`xdg-open "${url}"`, { stdio: 'ignore' });
    }
  } catch (e) {
    // bo qua loi khong mo duoc trinh duyet
  }
}

function checkServerReady(port, callback) {
  let finished = false;
  const done = (val) => {
    if (!finished) {
      finished = true;
      callback(val);
    }
  };

  const req = http.get(`http://127.0.0.1:${port}/api/system/daemon-status`, (res) => {
    if (res.statusCode === 200) {
      done(true);
    } else {
      done(false);
    }
  });

  req.on('error', () => done(false));
  req.setTimeout(1200, () => {
    req.destroy();
    done(false);
  });
}

function pollServerReady(port, maxAttempts, intervalMs, callback) {
  let attempts = 0;
  const timer = setInterval(() => {
    attempts++;
    checkServerReady(port, (isReady) => {
      if (isReady) {
        clearInterval(timer);
        callback(true);
      } else if (attempts >= maxAttempts) {
        clearInterval(timer);
        callback(false);
      }
    });
  }, intervalMs);
}

function findPythonCommand() {
  const candidates = ['python', 'py', 'python3'];
  for (const cmd of candidates) {
    try {
      const out = execSync(`${cmd} --version`, { stdio: 'pipe', encoding: 'utf-8' });
      if (out && (out.includes('Python 3') || out.includes('Python'))) {
        return cmd;
      }
    } catch (e) {
      // thu tiep
    }
  }
  return 'python';
}

function stopSystem() {
  console.log('[*] Dang tat he thong CTI Defense (Cong 8765, 8766, 11434)...');
  const pyCmd = findPythonCommand();
  
  if (fs.existsSync(SYSTEM_CTL_FILE)) {
    try {
      execSync(`"${pyCmd}" "${SYSTEM_CTL_FILE}" stop`, { stdio: 'inherit' });
      return;
    } catch (e) {}
  }

  // Fallback dung bang powershell / shell
  if (process.platform === 'win32') {
    try {
      execSync(
        `powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8765,8766,11434 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"`,
        { stdio: 'ignore' }
      );
      execSync(`taskkill /F /IM ollama.exe /T 2>nul`, { stdio: 'ignore' });
      execSync(`taskkill /F /IM ollama_llama_server.exe /T 2>nul`, { stdio: 'ignore' });
    } catch (e) {}
  } else {
    try {
      execSync(`lsof -ti:8765,8766,11434 | xargs kill -9`, { stdio: 'ignore' });
    } catch (e) {}
  }
  console.log('[OK] Da tat toan bo tien trinh he thong CTI Defense.');
}

function printStatus() {
  checkServerReady(PORT, (isReady) => {
    if (isReady) {
      console.log('==============================================================================');
      console.log('  STATUS: DANG HOAT DONG (ONLINE)');
      console.log('  - Web Dashboard : http://127.0.0.1:8765');
      console.log('  - WAF Proxy L7  : http://127.0.0.1:8766');
      console.log('==============================================================================');
    } else {
      console.log('==============================================================================');
      console.log('  STATUS: CHUA KHOI DONG (OFFLINE)');
      console.log('  De khoi dong, hay chay lenh: cti-defense (hoac cti)');
      console.log('==============================================================================');
    }
  });
}

function ensureDependencies(pyCmd) {
  try {
    execSync(`${pyCmd} -c "import fastapi, uvicorn, requests, docx"`, { stdio: 'ignore' });
  } catch (e) {
    console.log('[*] Dang kiem tra va tu dong cai dat cac thu vien Python can thiet...');
    const reqPath = path.join(ROOT_DIR, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      try {
        execSync(`${pyCmd} -m pip install -r "${reqPath}"`, { stdio: 'inherit' });
        console.log('[OK] Da cai dat day du cac thu vien Python.');
      } catch (err) {
        console.error('[CANH BAO] Khong the tu dong cai dat thu vien Python:', err.message);
      }
    }
  }
}

/**
 * Giu terminal lien tuc o trang thai interactive (tuong tu 9router)
 * Lang nghe Ctrl+C hoac 'q' de tat sach he thong va giai phong RAM/GPU
 */
function attachInteractiveConsole(targetDir, webUrl, childProcess = null) {
  let isShuttingDown = false;

  const performCleanExit = () => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log('\n==============================================================================');
    console.log('  DANG TAT TOAN BO HE THONG CTI DEFENSE VA GIAI PHONG RAM / GPU...');
    console.log('==============================================================================');

    if (childProcess) {
      try {
        childProcess.kill('SIGINT');
      } catch (e) {}
    }

    stopSystem();
    console.log('[HOAN TAT] He thong da tat sach se. Hen gap lai!');
    process.exit(0);
  };

  // Lang nghe cac su kien ngat de tat sach se
  process.on('SIGINT', performCleanExit);
  process.on('SIGTERM', performCleanExit);
  process.on('SIGHUP', performCleanExit);
  process.on('exit', () => {
    if (!isShuttingDown) {
      isShuttingDown = true;
      stopSystem();
    }
  });

  // Hien thi giao dien dieu khien Interactive
  console.clear ? console.clear() : console.log('\n'.repeat(5));
  console.log('==============================================================================');
  console.log('  HE THONG AN NINH MANG TU HANH CTI AGENTIC DEFENSE (v1.0.0)');
  console.log('==============================================================================');
  console.log('');
  console.log(`  [*] Thu muc du an muc tieu : ${targetDir}`);
  console.log(`  [*] Web Dashboard quan ly  : ${webUrl}`);
  console.log(`  [*] Trang thai tien trinh  : ONLINE (Dang giam sat thoi gian thuc)`);
  console.log('');
  console.log('  ==========================================================================');
  console.log('  TRUNG TAM DIEU KHIEN DONG LENH (INTERACTIVE CLI CONTROLLER):');
  console.log('');
  console.log('    - Nhan [o] hoac [Enter]  : Mo lai giao dien Web tren trinh duyet');
  console.log('    - Nhan [s]               : Kiem tra trang thai ket noi');
  console.log('    - Nhan [q] hoac [Ctrl+C] : Tat he thong, giai phong RAM/GPU va thoat');
  console.log('');
  console.log('  * HUONG DAN DUNG HE THONG:');
  console.log('    - Nhap to hop phim Ctrl+C tren ban phim; HOAC');
  console.log('    - Dong truc tiep cua so CMD nay de tu dong giai phong toan bo he thong!');
  console.log('  ==========================================================================');
  console.log('');
  console.log('[DANG CHAY] Server dang hoat dong ngam. Terminal dang giu tien trinh...');

  // Bat che do raw mode tren stdin neu la TTY
  if (process.stdin.isTTY) {
    try {
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding('utf8');

      process.stdin.on('data', (key) => {
        // Ctrl+C hoac 'q'
        if (key === '\u0003' || key.toLowerCase() === 'q') {
          performCleanExit();
        } else if (key === '\r' || key === '\n' || key.toLowerCase() === 'o') {
          console.log('[*] Dang mo lai Web Dashboard tren trinh duyet...');
          openBrowser(webUrl);
        } else if (key.toLowerCase() === 's') {
          checkServerReady(PORT, (ok) => {
            console.log(`[*] Trang thai: ${ok ? 'ONLINE (Ket noi on dinh)' : 'OFFLINE'}`);
          });
        }
      });
    } catch (e) {}
  }

  // Giu event loop Node luon hoat dong (khong bao gio tu dong thoat ra CMD prompt)
  setInterval(() => {
    checkServerReady(PORT, (isAlive) => {
      if (!isAlive && !isShuttingDown) {
        console.log('\n[THONG BAO] May chu backend da dung.');
        performCleanExit();
      }
    });
  }, 4000);
}

function startSystem() {
  const pyCmd = findPythonCommand();
  const targetDir = path.resolve(process.cwd());
  const webUrl = `http://127.0.0.1:8765/?target=${encodeURIComponent(targetDir)}`;

  ensureDependencies(pyCmd);

  // Kiem tra neu dang chay san roi
  checkServerReady(PORT, (alreadyRunning) => {
    if (alreadyRunning) {
      console.log('==============================================================================');
      console.log('  HE THONG CTI DEFENSE DANG HOAT DONG SAN TAI: http://127.0.0.1:8765');
      console.log(`  Cap nhat thu muc du an : ${targetDir}`);
      console.log('==============================================================================');

      const postData = JSON.stringify({ target_path: targetDir });
      const req = http.request({
        hostname: '127.0.0.1',
        port: PORT,
        path: '/api/system/set-target',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      }, () => {
        openBrowser(webUrl);
        // GIU TERMINAL CHAY LIEN TUC, KHONG THOAT RA PROMPT CMD
        attachInteractiveConsole(targetDir, webUrl, null);
      });

      req.on('error', () => {
        openBrowser(webUrl);
        attachInteractiveConsole(targetDir, webUrl, null);
      });

      req.write(postData);
      req.end();
      return;
    }

    // Neu chua chay -> Khoi dong moi
    console.log('==============================================================================');
    console.log('  DANG KHOI DONG HE THONG CTI AGENTIC DEFENSE...');
    console.log('==============================================================================');
    console.log(`[*] Su dung trinh thong dich Python: ${pyCmd}`);
    console.log(`[*] Thu muc goc he thong: ${ROOT_DIR}`);
    console.log(`[*] Thu muc du an muc tieu: ${targetDir}`);

    if (!fs.existsSync(APP_FILE)) {
      console.error(`[LOI] Khong tim thay tep khoi dong tai: ${APP_FILE}`);
      process.exit(1);
    }

    // Khoi dong Ollama ngam neu co
    try {
      if (process.platform === 'win32') {
        const ollamaCmd = 'where ollama >nul 2>nul && start /B "" ollama serve >nul 2>&1';
        execSync(`cmd /c "${ollamaCmd}"`, { stdio: 'ignore' });
      }
    } catch (e) {}

    // Khoi dong live_dashboard_app.py voi tham so --target
    console.log('[*] Dang khoi chay Live Dashboard & WAF Proxy (Cong 8765 & 8766)...');
    const child = spawn(pyCmd, [APP_FILE, '--target', targetDir], {
      cwd: SANDBOX_DIR,
      env: { ...process.env, CTI_TARGET_PROJECT: targetDir, PYTHONIOENCODING: 'utf-8' },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });

    let stdoutData = '';
    child.stdout.on('data', (d) => {
      stdoutData += d.toString();
    });
    child.stderr.on('data', (d) => {
      stdoutData += d.toString();
    });

    child.on('error', (err) => {
      console.error('[LOI] Khong the khoi dong tien trinh Python:', err.message);
      process.exit(1);
    });

    // Cho den khi server san sang
    pollServerReady(PORT, 30, 600, (isReady) => {
      if (isReady) {
        openBrowser(webUrl);
        // GIU TERMINAL CHAY LIEN TUC, KHONG THOAT RA PROMPT CMD
        attachInteractiveConsole(targetDir, webUrl, child);
      } else {
        console.error('[LOI] Qua thoi gian cho may chu khoi dong. Chi tiet log:');
        console.error(stdoutData.slice(-500));
        stopSystem();
        process.exit(1);
      }
    });
  });
}

// Router CLI
const arg = (process.argv[2] || '').toLowerCase().trim();

if (arg === 'stop' || arg === 'down' || arg === 'tat') {
  stopSystem();
} else if (arg === 'status' || arg === 'check') {
  printStatus();
} else if (arg === '--help' || arg === '-h' || arg === 'help') {
  console.log(`
Su dung: cti-defense [command] (hoac cti [command])

Lenh:
  cti-defense            Khoi dong toan bo he thong, giu terminal va tu dong mo trinh duyet
  cti-defense stop       Tat toan bo tien trinh dang chay (cong 8765, 8766, 11434)
  cti-defense status     Kiem tra he thong dang Online hay Offline
  cti-defense --help     Hien thi huong dan su dung
`);
} else {
  startSystem();
}
