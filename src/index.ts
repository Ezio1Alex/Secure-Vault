import { Hono, Context, Next } from 'hono';

type AppEnv = {
  Bindings: { DB: D1Database; };
  Variables: { username: string; };
};

const app = new Hono<AppEnv>();

app.get('/api/salt', async (c) => {
  try {
    let saltRow = await c.env.DB.prepare("SELECT value FROM vault_config WHERE key = 'master_salt'").first() as { value: string } | null;
    if (!saltRow) {
      const rawSalt = new Uint8Array(16);
      crypto.getRandomValues(rawSalt);
      const saltHex = Array.from(rawSalt).map(b => b.toString(16).padStart(2, '0')).join('');
      await c.env.DB.prepare("INSERT INTO vault_config (key, value) VALUES ('master_salt', ?)").bind(saltHex).run();
      return c.json({ salt: saltHex });
    }
    return c.json({ salt: saltRow.value });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

app.post('/api/register', async (c) => {
  const { username, auth_key } = await c.req.json();
  if (!username || !auth_key) return c.json({ error: "参数不完整" }, 400);

  try {
    const userCount = await c.env.DB.prepare("SELECT COUNT(*) as count FROM users").first() as { count: number } | null;
    if (userCount && userCount.count >= 5) {
      return c.json({ error: "🚨 注册通道已关闭：当前私有密码箱已达到最大允许账号数 (5个)！" }, 403);
    }
    const cleanUsername = username.trim().toLowerCase();
    await c.env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").bind(cleanUsername, auth_key).run();
    return c.json({ success: true });
  } catch (err: any) {
    if (err.message && err.message.includes("UNIQUE")) return c.json({ error: "该账号已被注册，请换一个用户名" }, 400);
    return c.json({ error: "注册失败: " + err.message }, 500);
  }
});

app.post('/api/login', async (c) => {
  const { username, auth_key } = await c.req.json();
  if (!username || !auth_key) return c.json({ error: "参数不完整" }, 400);

  const cleanUsername = username.trim().toLowerCase();
  try {
    const user = await c.env.DB.prepare("SELECT password_hash FROM users WHERE username = ?").bind(cleanUsername).first() as { password_hash: string } | null;
    if (!user || user.password_hash !== auth_key) return c.json({ error: "账号或密码错误" }, 401);
    return c.json({ success: true });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

const authMiddleware = async (c: Context<AppEnv>, next: Next) => {
  const username = c.req.header('x-username');
  const authKey = c.req.header('x-auth-key');
  if (!username || !authKey) return c.json({ error: "未授权的访问" }, 401);

  const cleanUsername = username.trim().toLowerCase();
  const user = await c.env.DB.prepare("SELECT password_hash FROM users WHERE username = ?").bind(cleanUsername).first() as { password_hash: string } | null;
  if (!user || user.password_hash !== authKey) return c.json({ error: "身份核验失败，请重新登录" }, 401);

  c.set('username', cleanUsername);
  await next();
};

app.get('/api/secrets', authMiddleware, async (c) => {
  const username = c.get('username');
  try {
    const { results } = await c.env.DB.prepare("SELECT id, encrypted_data, iv, updated_at FROM passwords WHERE username = ? ORDER BY id DESC").bind(username).all();
    return c.json(results);
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

app.post('/api/secrets', authMiddleware, async (c) => {
  const username = c.get('username');
  const { encrypted_data, iv } = await c.req.json();
  if (!encrypted_data || !iv) return c.json({ error: "参数不完整" }, 400);

  await c.env.DB.prepare("INSERT INTO passwords (username, encrypted_data, iv, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)").bind(username, encrypted_data, iv).run();
  return c.json({ success: true });
});

app.put('/api/secrets/:id', authMiddleware, async (c) => {
  const id = c.req.param('id');
  const username = c.get('username');
  const { encrypted_data, iv } = await c.req.json();
  if (!encrypted_data || !iv) return c.json({ error: "参数不完整" }, 400);

  try {
    const result = await c.env.DB.prepare("UPDATE passwords SET encrypted_data = ?, iv = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND username = ?").bind(encrypted_data, iv, id, username).run();
    if (result.meta.changes === 0) return c.json({ error: "记录不存在或无权修改" }, 404);
    return c.json({ success: true });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

app.delete('/api/secrets/:id', authMiddleware, async (c) => {
  const id = c.req.param('id');
  const username = c.get('username');
  try {
    await c.env.DB.prepare("DELETE FROM passwords WHERE id = ? AND username = ?").bind(id, username).run();
    return c.json({ success: true });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html lang="zh-CN" data-theme="light">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>私人密码箱</title>
        <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔒</text></svg>">
        <style>
            :root {
                --primary: #0071e3;
                --bg: #f5f5f7;
                --card-bg: #ffffff;
                --text: #1d1d1f;
                --text-secondary: #515154;
                --border: #d2d2d7;
                --item-bg: #fafafa;
                --item-border: #e5e5e7;
                --secondary-bg: #e8e8ed;
                --strength-weak: #ff453a;
                --strength-medium: #ff9f0a;
                --strength-strong: #0071e3;
                --strength-very-strong: #30d158;
                --warning-bg: #fff3cd;
                --warning-text: #856404;
                --warning-border: #ffc107;
            }
            [data-theme="dark"] {
                --bg: #1c1c1e;
                --card-bg: #2c2c2e;
                --text: #f5f5f7;
                --text-secondary: #a1a1a6;
                --border: #38383a;
                --item-bg: #3a3a3c;
                --item-border: #48484a;
                --secondary-bg: #3a3a3c;
                --warning-bg: #3a2e00;
                --warning-text: #ffd60a;
                --warning-border: #8b6900;
            }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); max-width: 800px; margin: 0 auto; padding: 20px; transition: background 0.3s, color 0.3s; }
            .card { background: var(--card-bg); padding: 30px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); margin-bottom: 20px; transition: background 0.3s; }
            h2, h3 { margin-top: 0; font-weight: 600; text-align: center; }
            input, select, button { padding: 12px 16px; margin: 8px 0; border: 1px solid var(--border); border-radius: 8px; font-size: 15px; box-sizing: border-box; width: 100%; background: var(--card-bg); color: var(--text); transition: background 0.3s, color 0.3s; }
            select { cursor: pointer; }
            button { background: var(--primary); color: white; border: none; cursor: pointer; font-weight: 600; transition: background 0.2s; }
            button:hover { background: #0077ed; }
            button.secondary { background: var(--secondary-bg); color: var(--text); width: auto; }
            button.secondary:hover { background: var(--border); }
            button.danger { background: #ff453a; width: auto; }
            button.danger:hover { background: #ff3b30; }
            button.small-btn { padding: 5px 10px; font-size: 12px; margin-left: 5px; }
            .form-group { margin-bottom: 15px; }
            .form-group label { display: block; margin-bottom: 6px; font-size: 14px; font-weight: 500; color: var(--text-secondary); }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
            .secret-item { background: var(--item-bg); border: 1px solid var(--item-border); border-radius: 10px; padding: 18px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: flex-start; transition: background 0.3s; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #e2f6ea; color: #1a7f37; }
            .copy-btn { padding: 5px 10px; font-size: 12px; margin-left: 5px; }
            .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .logo { font-size: 22px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
            .search-bar { padding: 12px; margin-bottom: 15px; border: 1px solid var(--border); border-radius: 8px; font-size: 15px; width: 100%; box-sizing: border-box; background: var(--card-bg); color: var(--text); }
            .generator-container { background: var(--card-bg); border: 1px dashed var(--border); padding: 15px; border-radius: 8px; margin-top: 10px; }
            .generator-container input[type="checkbox"] { width: auto; margin-right: 5px; vertical-align: middle; }
            .generator-container label { font-size: 14px; margin-right: 15px; cursor: pointer; white-space: nowrap; }
            .generator-grid { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 8px; }
            .toggle-link { text-align: center; margin-top: 15px; font-size: 14px; color: var(--primary); cursor: pointer; text-decoration: underline; }
            .file-upload-label { display: inline-block; padding: 10px 16px; background: var(--secondary-bg); color: var(--text); border-radius: 8px; cursor: pointer; font-size: 15px; font-weight: 600; transition: background 0.2s; text-align: center; margin: 8px 0; }
            .file-upload-label:hover { background: var(--border); }

            /* 深色模式切换 */
            .theme-toggle { background: none; border: 1px solid var(--border); color: var(--text); font-size: 18px; padding: 6px 10px; border-radius: 8px; cursor: pointer; width: auto; margin: 0; }
            .theme-toggle:hover { background: var(--secondary-bg); }

            /* 密码强度条 */
            .strength-bar { height: 4px; border-radius: 2px; margin-top: 4px; transition: width 0.3s, background 0.3s; }
            .strength-label { font-size: 12px; margin-top: 2px; font-weight: 500; }
            .strength-weak { color: var(--strength-weak); }
            .strength-medium { color: var(--strength-medium); }
            .strength-strong { color: var(--strength-strong); }
            .strength-very-strong { color: var(--strength-very-strong); }

            /* 排序控件 */
            .sort-bar { display: flex; gap: 10px; align-items: center; margin-bottom: 15px; }
            .sort-bar label { font-size: 14px; color: var(--text-secondary); white-space: nowrap; }
            .sort-bar select { width: auto; padding: 6px 10px; margin: 0; font-size: 14px; }

            /* 锁定警告 */
            .lock-warning { display: none; background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border); padding: 10px 16px; border-radius: 8px; font-size: 14px; text-align: center; margin-bottom: 15px; }

            /* 相对时间戳 */
            .time-ago { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }

            /* 编辑按钮行 */
            .item-actions { display: flex; flex-direction: column; gap: 6px; flex-shrink: 0; margin-left: 15px; }
        </style>
    </head>
    <body>

        <div id="lockWarning" class="lock-warning">⏰ 30 秒后因闲置自动锁定</div>

        <div class="card" id="authCard" style="max-width: 400px; margin: 80px auto 0;">
            <h2 id="authTitle">🔑 密码箱登录</h2>
            <div class="form-group">
                <label>登录账号 (Username)</label>
                <input type="text" id="usernameInput" placeholder="输入你的账号名称">
            </div>
            <div class="form-group">
                <label>登录密码 (Master Password)</label>
                <input type="password" id="passwordInput" placeholder="输入登录密码" onkeyup="if(event.key==='Enter') handleAuth()">
            </div>
            <div class="form-group" id="confirmPasswordGroup" style="display: none;">
                <label>确认密码 (Confirm Password)</label>
                <input type="password" id="confirmPasswordInput" placeholder="请再次输入登录密码" onkeyup="if(event.key==='Enter') handleAuth()">
            </div>
            <button id="authBtn" onclick="handleAuth()" style="margin-top: 10px;">登 录</button>
            <div class="toggle-link" id="authToggle" onclick="toggleAuthMode()">没有账号？立即注册</div>
        </div>

        <div id="mainWorkspace" style="display: none;">
            <div class="header">
                <div class="logo">🔒 私人密码箱 <span style="font-size: 13px; color: var(--text-secondary); font-weight: normal;" id="currentUserLabel"></span></div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" title="切换深色模式">🌙</button>
                    <button class="danger" onclick="logout()" style="padding: 6px 12px; font-size: 13px; margin: 0;">安全退出</button>
                </div>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 10px;">💽 数据备份与恢复 (离线 JSON)</h3>
                <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 15px;">零知识架构下若遗忘密码数据将永久丢失。请务必定期导出未加密的 JSON 文件，存放在 U 盘等安全离线环境中。</p>
                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <button class="secondary" onclick="exportJSON()" style="margin: 0;">⬇️ 导出明文备份</button>
                    <label for="importFile" class="file-upload-label" style="margin: 0;">⬆️ 从备份恢复导入</label>
                    <input type="file" id="importFile" accept=".json" style="display: none;" onchange="importJSON(event)">
                </div>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 15px;" id="saveFormTitle">➕ 保存新账号密码</h3>
                <div class="grid">
                    <input type="text" id="site" placeholder="网站域名 (如 github.com)">
                    <input type="text" id="editUsername" placeholder="账号 / 邮箱 / 手机号">
                </div>
                <div style="display: flex; gap: 10px; align-items: center;">
                    <input type="text" id="password" placeholder="密码明文" style="flex-grow: 1;">
                    <button class="secondary" onclick="toggleGenerator()" style="white-space: nowrap; margin:0;">生成器选项</button>
                </div>
                <!-- 密码强度条 -->
                <div id="strengthIndicator" style="display: none; margin-top: 4px;">
                    <div class="strength-bar" id="strengthBar" style="width: 0%; background: transparent;"></div>
                    <div class="strength-label" id="strengthLabel"></div>
                </div>

                <div style="margin-top: 10px;">
                    <input type="text" id="note" placeholder="备注 (选填，如：绑定的手机号、安全问题答案等)">
                </div>

                <div id="generatorPanel" class="generator-container" style="display: none;">
                    <strong>🛠️ 本地高强度密码生成器</strong>
                    <div style="margin-top: 10px;">
                        <label>
                            长度: <input type="number" id="genLength" value="16" min="6" max="64" style="width: 60px; padding: 4px 8px; display:inline-block; margin-left: 5px;">
                        </label>
                    </div>
                    <div class="generator-grid">
                        <label><input type="checkbox" id="genUpper" checked> 大写字母</label>
                        <label><input type="checkbox" id="genLower" checked> 小写字母</label>
                        <label><input type="checkbox" id="genNumber" checked> 数字</label>
                        <label><input type="checkbox" id="genSymbols" checked> 特殊符号</label>
                    </div>
                    <button class="secondary" onclick="generatePassword()" style="font-size: 12px; padding: 6px 12px; margin-top: 10px; width: auto;">生成并填入</button>
                </div>

                <div style="display: flex; gap: 10px;">
                    <button onclick="saveSecret()" style="margin-top: 15px; flex-grow: 1;" id="saveBtn">加密并存入云端</button>
                    <button class="secondary" onclick="cancelEdit()" id="cancelEditBtn" style="margin-top: 15px; display: none;">取消编辑</button>
                </div>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 15px;">📋 已保存的凭证</h3>
                <div class="sort-bar">
                    <label>排序：</label>
                    <select id="sortSelect" onchange="renderSecrets(getFilteredAndSorted())">
                        <option value="newest">最近添加</option>
                        <option value="oldest">最早添加</option>
                        <option value="alpha-asc">网站名 A→Z</option>
                        <option value="alpha-desc">网站名 Z→A</option>
                        <option value="updated">最近更新</option>
                    </select>
                    <input type="text" id="searchBar" class="search-bar" placeholder="🔍 搜索网站、账号名称或备注..." oninput="filterSecrets()" style="margin: 0; flex-grow: 1;">
                </div>
                <div id="list"></div>
            </div>
        </div>

        <script>
            let cachedMasterKey = null; let cachedAuthKey = null; let cachedUsername = null;
            let dbSalt = null; let allDecryptedSecrets = []; let isRegisterMode = false;
            let editTargetId = null; /* 正在编辑的记录 id */

            /* ====== 自动锁定 ====== */
            let lastActivity = Date.now();
            let lockCheckTimer = null;

            function resetActivity() { lastActivity = Date.now(); }
            document.addEventListener('mousemove', resetActivity);
            document.addEventListener('keydown', resetActivity);
            document.addEventListener('click', resetActivity);
            document.addEventListener('touchstart', resetActivity);
            document.addEventListener('scroll', resetActivity);

            function startLockTimer() {
                const WARNING_MS = 150000;  /* 2分30秒 */
                const LOCK_MS = 180000;     /* 3分钟 */
                const warningEl = document.getElementById('lockWarning');

                function check() {
                    const elapsed = Date.now() - lastActivity;
                    if (elapsed >= LOCK_MS) {
                        warningEl.style.display = 'none';
                        doAutoLock();
                        return;
                    }
                    if (elapsed >= WARNING_MS) {
                        const remaining = Math.ceil((LOCK_MS - elapsed) / 1000);
                        warningEl.textContent = '⏰ ' + remaining + ' 秒后因闲置自动锁定';
                        warningEl.style.display = 'block';
                    } else {
                        warningEl.style.display = 'none';
                    }
                    lockCheckTimer = setTimeout(check, 1000);
                }
                check();
            }

            function doAutoLock() {
                cachedMasterKey = null; cachedAuthKey = null; cachedUsername = null;
                allDecryptedSecrets = [];
                document.getElementById('mainWorkspace').style.display = 'none';
                document.getElementById('authCard').style.display = 'block';
                document.getElementById('list').innerHTML = '';
                if (lockCheckTimer) clearTimeout(lockCheckTimer);
                alert('已自动锁定，请重新登录');
            }

            /* ====== 深色模式 ====== */
            function getPreferredTheme() {
                return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }

            function applyTheme(theme) {
                document.documentElement.setAttribute('data-theme', theme);
                document.getElementById('themeToggle').textContent = theme === 'dark' ? '☀️' : '🌙';
                localStorage.setItem('vault-theme', theme);
            }

            function toggleTheme() {
                const current = document.documentElement.getAttribute('data-theme');
                applyTheme(current === 'dark' ? 'light' : 'dark');
            }

            /* 初始化主题 */
            (function initTheme() {
                try {
                    const saved = localStorage.getItem('vault-theme');
                    if (saved) {
                        applyTheme(saved);
                    } else {
                        applyTheme(getPreferredTheme());
                    }
                } catch (e) {
                    /* localStorage 不可用时静默使用系统主题 */
                    applyTheme(getPreferredTheme());
                }
            })();

            /* ====== Salt ====== */
            async function fetchMasterSalt() {
                const res = await fetch('/api/salt');
                const data = await res.json();
                dbSalt = data.salt;
            }

            function hexToBytes(hex) {
                const bytes = new Uint8Array(hex.length / 2);
                for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
                return bytes;
            }

            async function deriveKey(password, saltHex) {
                const encoder = new TextEncoder();
                const passwordKey = await window.crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
                const saltBytes = hexToBytes(saltHex);
                return window.crypto.subtle.deriveKey(
                    { name: "PBKDF2", salt: saltBytes, iterations: 600000, hash: "SHA-256" },
                    passwordKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
                );
            }

            async function deriveAuthKey(username, password, saltHex) {
                const encoder = new TextEncoder();
                const combined = encoder.encode(username.trim().toLowerCase() + ":" + password + ":" + saltHex);
                const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            }

            /* ====== 密码强度 ====== */
            function evaluatePasswordStrength(pwd) {
                if (!pwd) return { level: 0, label: '', width: 0, cls: '' };
                const hasUpper = /[A-Z]/.test(pwd);
                const hasLower = /[a-z]/.test(pwd);
                const hasDigit = /[0-9]/.test(pwd);
                const hasSymbol = /[^A-Za-z0-9]/.test(pwd);
                const types = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
                const len = pwd.length;

                if (len <= 6 || types === 1) return { level: 1, label: '弱', width: 25, cls: 'strength-weak' };
                if (len >= 8 && types >= 2) {
                    if (len >= 16 && types === 4) return { level: 4, label: '非常强', width: 100, cls: 'strength-very-strong' };
                    if (len >= 12 && types >= 3) return { level: 3, label: '强', width: 75, cls: 'strength-strong' };
                    return { level: 2, label: '中', width: 50, cls: 'strength-medium' };
                }
                return { level: 1, label: '弱', width: 25, cls: 'strength-weak' };
            }

            function updateStrengthIndicator() {
                const pwd = document.getElementById('password').value;
                const indicator = document.getElementById('strengthIndicator');
                const bar = document.getElementById('strengthBar');
                const label = document.getElementById('strengthLabel');

                if (!pwd) { indicator.style.display = 'none'; return; }

                const result = evaluatePasswordStrength(pwd);
                indicator.style.display = 'block';
                bar.style.width = result.width + '%';
                var colorMap = {
                    '弱': 'var(--strength-weak)',
                    '中': 'var(--strength-medium)',
                    '强': 'var(--strength-strong)',
                    '非常强': 'var(--strength-very-strong)'
                };
                bar.style.background = colorMap[result.label] || 'transparent';
                label.textContent = '密码强度：' + result.label;
                label.className = 'strength-label ' + result.cls;
            }

            /* ====== 相对时间 ====== */
            function timeAgo(dateStr) {
                if (!dateStr) return '';
                var now = new Date();
                var date = new Date(dateStr + 'Z'); /* D1 返回的是 UTC，补 Z */
                var diff = Math.floor((now - date) / 1000);
                if (diff < 60) return '刚刚';
                if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
                if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
                if (diff < 2592000) return Math.floor(diff / 86400) + ' 天前';
                return Math.floor(diff / 2592000) + ' 个月前';
            }

            /* ====== 登录 / 注册 ====== */
            function toggleAuthMode() {
                isRegisterMode = !isRegisterMode;
                document.getElementById('authTitle').innerText = isRegisterMode ? "📝 注册新账号" : "🔑 密码箱登录";
                document.getElementById('authBtn').innerText = isRegisterMode ? "注 册 并 登 录" : "登 录";
                document.getElementById('authToggle').innerText = isRegisterMode ? "已有账号？立即登录" : "没有账号？立即注册";
                document.getElementById('confirmPasswordGroup').style.display = isRegisterMode ? "block" : "none";
            }

            async function handleAuth() {
                const username = document.getElementById('usernameInput').value.trim();
                const password = document.getElementById('passwordInput').value;

                if (!username || !password) return alert("账号和密码不能为空！");

                if (isRegisterMode) {
                    const confirmPassword = document.getElementById('confirmPasswordInput').value;
                    if (password !== confirmPassword) {
                        return alert("两次输入的密码不一致，请重新检查！");
                    }
                }

                try {
                    if (!dbSalt) await fetchMasterSalt();
                    document.getElementById('authBtn').innerText = "计算安全密钥中...";

                    setTimeout(async () => {
                        try {
                            const authKey = await deriveAuthKey(username, password, dbSalt);
                            const masterKey = await deriveKey(password, dbSalt);

                            if (isRegisterMode) {
                                const res = await fetch('/api/register', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ username, auth_key: authKey })
                                });
                                const data = await res.json();
                                if (!res.ok) throw new Error(data.error || "注册失败！");
                                alert("🎉 注册成功！");
                            } else {
                                const res = await fetch('/api/login', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ username, auth_key: authKey })
                                });
                                const data = await res.json();
                                if (!res.ok) throw new Error(data.error || "账号或密码错误！");
                            }

                            cachedUsername = username; cachedAuthKey = authKey; cachedMasterKey = masterKey;
                            document.getElementById('authCard').style.display = "none";
                            document.getElementById('mainWorkspace').style.display = "block";
                            document.getElementById('currentUserLabel').innerText = "@" + username;

                            resetActivity();
                            startLockTimer();
                            await loadSecrets();
                        } catch (err) {
                            alert(err.message);
                        } finally {
                            document.getElementById('authBtn').innerText = isRegisterMode ? "注 册 并 登 录" : "登 录";
                        }
                    }, 50);
                } catch (e) {
                    alert("网络错误: " + e.message);
                }
            }

            function logout() {
                cachedMasterKey = null; cachedAuthKey = null; cachedUsername = null;
                allDecryptedSecrets = []; editTargetId = null;
                document.getElementById('passwordInput').value = '';
                document.getElementById('confirmPasswordInput').value = '';
                document.getElementById('usernameInput').value = '';
                document.getElementById('searchBar').value = '';
                document.getElementById('lockWarning').style.display = 'none';
                if (lockCheckTimer) clearTimeout(lockCheckTimer);

                isRegisterMode = false;
                document.getElementById('authTitle').innerText = "🔑 密码箱登录";
                document.getElementById('authBtn').innerText = "登 录";
                document.getElementById('authToggle').innerText = "没有账号？立即注册";
                document.getElementById('confirmPasswordGroup').style.display = "none";

                document.getElementById('authCard').style.display = "block";
                document.getElementById('mainWorkspace').style.display = "none";
                document.getElementById('generatorPanel').style.display = "none";
                document.getElementById('list').innerHTML = '';
                cancelEdit();
            }

            /* ====== 保存 / 编辑 ====== */
            function cancelEdit() {
                editTargetId = null;
                document.getElementById('saveFormTitle').textContent = '➕ 保存新账号密码';
                document.getElementById('saveBtn').textContent = '加密并存入云端';
                document.getElementById('cancelEditBtn').style.display = 'none';
                document.getElementById('site').value = '';
                document.getElementById('editUsername').value = '';
                document.getElementById('password').value = '';
                document.getElementById('note').value = '';
                updateStrengthIndicator();
            }

            async function saveSecret() {
                if (!cachedMasterKey || !cachedAuthKey) return alert("登录过期！");
                const site = document.getElementById('site').value.trim();
                const username = document.getElementById('editUsername').value.trim();
                const password = document.getElementById('password').value;
                const note = document.getElementById('note').value.trim();

                if (!site || !username || !password) return alert("网站名、账号和密码必填！");

                try {
                    const iv = window.crypto.getRandomValues(new Uint8Array(12));
                    const encoder = new TextEncoder();
                    const payload = JSON.stringify({ site, username, password, note });
                    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cachedMasterKey, encoder.encode(payload));

                    const encrypted_data = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
                    const iv_str = btoa(String.fromCharCode(...iv));

                    if (editTargetId) {
                        /* 更新已有记录 */
                        const res = await fetch('/api/secrets/' + editTargetId, {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json', 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey },
                            body: JSON.stringify({ encrypted_data, iv: iv_str })
                        });
                        if (!res.ok) { const err = await res.json(); throw new Error(err.error); }
                        cancelEdit();
                    } else {
                        /* 新增 */
                        const res = await fetch('/api/secrets', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey },
                            body: JSON.stringify({ encrypted_data, iv: iv_str })
                        });
                        if (!res.ok) { const err = await res.json(); throw new Error(err.error); }
                        document.getElementById('site').value = '';
                        document.getElementById('editUsername').value = '';
                        document.getElementById('password').value = '';
                        document.getElementById('note').value = '';
                        updateStrengthIndicator();
                    }
                    await loadSecrets();
                } catch (e) {
                    alert("保存失败: " + e.message);
                }
            }

            async function loadSecrets() {
                if (!cachedMasterKey || !cachedAuthKey) return;
                const res = await fetch('/api/secrets', { headers: { 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey }});
                if (!res.ok) return logout();

                const rawData = await res.json();
                const decoder = new TextDecoder();
                allDecryptedSecrets = [];

                for (let item of rawData) {
                    try {
                        const iv = Uint8Array.from(atob(item.iv), c => c.charCodeAt(0));
                        const encryptedBytes = Uint8Array.from(atob(item.encrypted_data), c => c.charCodeAt(0));
                        const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, cachedMasterKey, encryptedBytes);

                        const credentials = JSON.parse(decoder.decode(decrypted));
                        allDecryptedSecrets.push({
                            id: item.id,
                            site: credentials.site,
                            username: credentials.username,
                            password: credentials.password,
                            note: credentials.note || '',
                            updated_at: item.updated_at || null
                        });
                    } catch (e) {}
                }
                renderSecrets(getFilteredAndSorted());
            }

            /* ====== 排序 & 搜索 ====== */
            function getFilteredAndSorted() {
                const query = document.getElementById('searchBar').value.toLowerCase();
                const sortBy = document.getElementById('sortSelect').value;

                var filtered = allDecryptedSecrets.filter(function(item) {
                    return item.site.toLowerCase().includes(query) ||
                           item.username.toLowerCase().includes(query) ||
                           item.note.toLowerCase().includes(query);
                });

                filtered.sort(function(a, b) {
                    switch (sortBy) {
                        case 'newest': return b.id - a.id;
                        case 'oldest': return a.id - b.id;
                        case 'alpha-asc': return a.site.localeCompare(b.site);
                        case 'alpha-desc': return b.site.localeCompare(a.site);
                        case 'updated': return (b.updated_at || '').localeCompare(a.updated_at || '');
                        default: return b.id - a.id;
                    }
                });
                return filtered;
            }

            function filterSecrets() {
                renderSecrets(getFilteredAndSorted());
            }

            function renderSecrets(secrets) {
                const listDiv = document.getElementById('list');
                listDiv.innerHTML = '';
                if (secrets.length === 0) {
                    listDiv.innerHTML = '<p style="color:var(--text-secondary); text-align:center;">此账号箱子中暂无密码记录。</p>';
                    return;
                }
                secrets.forEach(function(item) {
                    const noteHtml = item.note ? '<div style="margin: 8px 0 0; font-size: 13px; color:var(--text-secondary); background: var(--item-bg); padding: 8px; border-radius: 6px; border: 1px solid var(--border);">📝 <strong>备注:</strong> ' + escapeHtml(item.note) + '</div>' : '';
                    const timeHtml = '<div class="time-ago">🕐 ' + timeAgo(item.updated_at) + '</div>';

                    listDiv.innerHTML += \`
                        <div class="secret-item">
                            <div style="flex-grow: 1;">
                                <span class="badge">已解密</span>
                                <strong style="font-size: 16px; display:block; color:var(--text);">\${escapeHtml(item.site)}</strong>
                                <div style="margin: 6px 0 0; font-size: 14px; color:var(--text-secondary);">
                                    账号: <span id="user-\${item.id}">\${escapeHtml(item.username)}</span>
                                    <button class="secondary copy-btn" onclick="copyToClipboard('user-\${item.id}')">复制</button>
                                </div>
                                <div style="margin: 4px 0 0; font-size: 14px; color:var(--text-secondary);">
                                    密码: <span id="pwd-\${item.id}" style="-webkit-text-security: disc;">\${escapeHtml(item.password)}</span>
                                    <button class="secondary copy-btn" onclick="togglePasswordVisibility('pwd-\${item.id}', this)">显示</button>
                                    <button class="secondary copy-btn" onclick="copyToClipboard('pwd-\${item.id}')">复制</button>
                                </div>
                                \${noteHtml}
                                \${timeHtml}
                            </div>
                            <div class="item-actions">
                                <button class="secondary small-btn" onclick="editSecret(\${item.id})" style="width: auto;">✏️ 编辑</button>
                                <button class="danger small-btn" onclick="deleteSecret(\${item.id})" style="width: auto;">删除</button>
                            </div>
                        </div>
                    \`;
                });
            }

            /* ====== 编辑功能 ====== */
            function editSecret(id) {
                var item = allDecryptedSecrets.find(function(s) { return s.id === id; });
                if (!item) return;

                editTargetId = id;
                document.getElementById('saveFormTitle').textContent = '✏️ 编辑密码 #' + id;
                document.getElementById('saveBtn').textContent = '更新并保存';
                document.getElementById('cancelEditBtn').style.display = 'inline-block';
                document.getElementById('site').value = item.site;
                document.getElementById('editUsername').value = item.username;
                document.getElementById('password').value = item.password;
                document.getElementById('note').value = item.note;
                updateStrengthIndicator();
                /* 滚动到表单 */
                document.querySelector('.card:nth-of-type(3)').scrollIntoView({ behavior: 'smooth' });
            }

            async function deleteSecret(id) {
                if (!cachedAuthKey) return;
                if (confirm("确定要永久删除这条记录吗？数据不可恢复！")) {
                    const res = await fetch('/api/secrets/' + id, { method: 'DELETE', headers: { 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey }});
                    if (res.ok) {
                        if (editTargetId === id) cancelEdit();
                        await loadSecrets();
                    }
                }
            }

            /* ====== 密码生成器 ====== */
            function toggleGenerator() {
                const panel = document.getElementById('generatorPanel');
                panel.style.display = panel.style.display === "none" ? "block" : "none";
            }

            function generatePassword() {
                const length = parseInt(document.getElementById('genLength').value) || 16;
                let chars = '';
                if (document.getElementById('genUpper').checked) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
                if (document.getElementById('genLower').checked) chars += 'abcdefghijklmnopqrstuvwxyz';
                if (document.getElementById('genNumber').checked) chars += '0123456789';
                if (document.getElementById('genSymbols').checked) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
                if (!chars) return alert("请至少选择一种字符集！");

                let password = '';
                const randomValues = new Uint32Array(length);
                window.crypto.getRandomValues(randomValues);
                for (let i = 0; i < length; i++) password += chars[randomValues[i] % chars.length];
                document.getElementById('password').value = password;
                updateStrengthIndicator();
            }

            function togglePasswordVisibility(id, btn) {
                const el = document.getElementById(id);
                if (el.style.webkitTextSecurity === "disc" || el.style.webkitTextSecurity === "") {
                    el.style.webkitTextSecurity = "none"; btn.innerText = "隐藏";
                } else {
                    el.style.webkitTextSecurity = "disc"; btn.innerText = "显示";
                }
            }

            function copyToClipboard(elementId) {
                navigator.clipboard.writeText(document.getElementById(elementId).textContent);
                showToast('已复制');
            }

            function showToast(msg) {
                var el = document.getElementById('toast');
                if (!el) {
                    el = document.createElement('div');
                    el.id = 'toast';
                    el.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:8px 20px;border-radius:20px;font-size:14px;z-index:9999;opacity:0;transition:opacity 0.3s;pointer-events:none;';
                    document.body.appendChild(el);
                }
                el.textContent = msg;
                el.style.opacity = '1';
                clearTimeout(el._timer);
                el._timer = setTimeout(function() { el.style.opacity = '0'; }, 1500);
            }

            function escapeHtml(string) {
                return String(string).replace(/[&<>"']/g, function (s) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[s]; });
            }

            /* ====== 导出 / 导入 ====== */
            function exportJSON() {
                if (allDecryptedSecrets.length === 0) return alert("当前密码箱为空，没有需要导出的数据！");
                const exportData = allDecryptedSecrets.map(function(item) {
                    return { site: item.site, username: item.username, password: item.password, note: item.note };
                });
                const dataStr = JSON.stringify(exportData, null, 2);
                const blob = new Blob([dataStr], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'Vault_Backup_' + new Date().toISOString().split('T')[0] + '.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }

            async function importJSON(event) {
                const file = event.target.files[0];
                if (!file) return;
                if (!confirm("导入操作将会把 JSON 备份文件中的密码逐条加密上传至云端，确定执行吗？\\n(建议在全新的空账号中执行导入，避免数据重复)")) {
                    event.target.value = ''; return;
                }

                const reader = new FileReader();
                reader.onload = async function(e) {
                    try {
                        const importedData = JSON.parse(e.target.result);
                        if (!Array.isArray(importedData)) throw new Error("JSON 格式错误，应为一个数组格式");

                        let successCount = 0;
                        document.getElementById('importFile').disabled = true;

                        for (const item of importedData) {
                            if (!item.site || !item.username || !item.password) continue;
                            const iv = window.crypto.getRandomValues(new Uint8Array(12));
                            const encoder = new TextEncoder();
                            const payload = JSON.stringify({
                                site: item.site,
                                username: item.username,
                                password: item.password,
                                note: item.note || ''
                            });
                            const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cachedMasterKey, encoder.encode(payload));
                            const encrypted_data = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
                            const iv_str = btoa(String.fromCharCode(...iv));

                            const res = await fetch('/api/secrets', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json', 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey },
                                body: JSON.stringify({ encrypted_data, iv: iv_str })
                            });
                            if (res.ok) successCount++;
                        }
                        alert("✅ 导入完成！成功将 " + successCount + " 条记录加密并存入当前账号。");
                        await loadSecrets();
                    } catch (err) {
                        alert("导入失败: 文件解析错误或网络异常 (" + err.message + ")");
                    } finally {
                        event.target.value = ''; document.getElementById('importFile').disabled = false;
                    }
                };
                reader.readAsText(file);
            }

            /* 密码输入框实时检测强度 */
            document.getElementById('password').addEventListener('input', updateStrengthIndicator);

            fetchMasterSalt();
        </script>
    </body>
    </html>
  `);
});

export default app;
