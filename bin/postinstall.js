#!/usr/bin/env node
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const rootDir = path.resolve(__dirname, '..');
const reqPath = path.join(rootDir, 'requirements.txt');

console.log('[CTI DEFENSE] Dang thiet lap moi truong Python...');
const candidates = ['python', 'py', 'python3'];
let pyCmd = 'python';
for (const c of candidates) {
  try {
    const out = execSync(`${c} --version`, { stdio: 'pipe' }).toString();
    if (out.includes('Python')) {
      pyCmd = c;
      break;
    }
  } catch (e) {}
}

if (fs.existsSync(reqPath)) {
  try {
    execSync(`${pyCmd} -m pip install -r "${reqPath}" --disable-pip-version-check`, { stdio: 'inherit' });
    console.log('[OK] Da cai dat xong cac thu vien an ninh mang Python.');
  } catch (e) {
    console.log('[CANH BAO] Ban co the tu dong cai dat bo sung khi chay lenh cti.');
  }
}
