#!/usr/bin/env node

/**
 * CTI Agentic Defense System - Global CLI Launcher
 * Ho tro khoi chay qua npm: cti-defense hoac cti
 */

const { spawn, execSync } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');

const ROOT_DIR = path.resolve(__dirname, '..');
const SANDBOX_DIR = path.join(ROOT_DIR, 'khang_sandbox_full_cti');
const APP_FILE = path.join(SANDBOX_DIR, 'live_dashboard_app.py');
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
  console.log('[*] Dang tat he thong CTI Defense (Cong 8765 & 8766)...');
  if (process.platform === 'win32') {
    try {
      execSync(
        `powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8765,8766 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"`,
        { stdio: 'ignore' }
      );
    } catch (e) {}
  } else {
    try {
      execSync(`lsof -ti:8765,8766 | xargs kill -9`, { stdio: 'ignore' });
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

function startSystem() {
  const pyCmd = findPythonCommand();

  // Kiem tra neu dang chay san roi
  checkServerReady(PORT, (alreadyRunning) => {
    if (alreadyRunning) {
      console.log('==============================================================================');
      console.log('  HE THONG CTI DEFENSE DANG HOAT DONG SAN TAI: http://127.0.0.1:8765');
      console.log('==============================================================================');
      console.log('[*] Dang mo trinh duyet...');
      openBrowser('http://127.0.0.1:8765');
      return;
    }

    console.log('==============================================================================');
    console.log('  🚀 DANG KHOI DONG HE THONG CTI AGENTIC DEFENSE...');
    console.log('==============================================================================');
    console.log(`[*] Su dung trinh thong dich Python: ${pyCmd}`);
    console.log(`[*] Thu muc goc: ${ROOT_DIR}`);

    // Kiem tra thu muc Sandbox
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

    // Khoi dong live_dashboard_app.py
    console.log('[*] Dang khoi chay Live Dashboard & WAF Proxy (Cong 8765 & 8766)...');
    const child = spawn(pyCmd, [APP_FILE], {
      cwd: SANDBOX_DIR,
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
    pollServerReady(PORT, 25, 600, (isReady) => {
      if (isReady) {
        console.clear ? console.clear() : console.log('\n'.repeat(10));
        console.log('==============================================================================');
        console.log('  🚀 HE THONG AN NINH MANG TU HANH CTI AGENTIC DEFENSE (KHOI DONG THANH CONG)');
        console.log('==============================================================================');
        console.log('');
        console.log('  [OK] CTI Defense Engine & WAF Reverse Proxy dang hoat dong tai cong 8766.');
        console.log('  [OK] Da tu dong mo trinh duyet Web Dashboard.');
        console.log('');
        console.log('  ==========================================================================');
        console.log('  👉 DUONG LINK TRUY CAP TRUC TIEP:');
        console.log('');
        console.log('       http://127.0.0.1:8765');
        console.log('');
        console.log('  ==========================================================================');
        console.log('');
        console.log('  * BUOC 1 TREN WEB LA: [ QUET DU AN (SCAN CODEBASE) ]');
        console.log('    Chi can nhap duong dan thu muc hoac link Git, he thong se tu dong lam het.');
        console.log('');
        console.log('  * CAC LENH HO TRO:');
        console.log('    - cti-defense         : Khoi dong & mo Dashboard');
        console.log('    - cti-defense stop    : Tat he thong');
        console.log('    - cti-defense status  : Kiem tra trang thai');
        console.log('==============================================================================');
        console.log('');
        console.log('Nhan Ctrl+C de dung he thong.');

        openBrowser('http://127.0.0.1:8765');
      } else {
        console.error('[LOI] Qua thoi gian cho may chu khoi dong. Chi tiet log:');
        console.error(stdoutData.slice(-500));
      }
    });

    process.on('SIGINT', () => {
      console.log('\n[*] Dang dung he thong...');
      try {
        child.kill();
      } catch (e) {}
      stopSystem();
      process.exit(0);
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
  cti-defense            Khoi dong toan bo he thong va tu dong mo trinh duyet
  cti-defense stop       Tat toan bo tien trinh dang chay (cong 8765 & 8766)
  cti-defense status     Kiem tra he thong dang Online hay Offline
  cti-defense --help     Hien thi huong dan su dung
`);
} else {
  startSystem();
}
