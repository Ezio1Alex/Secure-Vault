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
    const { results } = await c.env.DB.prepare("SELECT id, encrypted_data, iv FROM passwords WHERE username = ? ORDER BY id DESC").bind(username).all();
    return c.json(results);
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

app.post('/api/secrets', authMiddleware, async (c) => {
  const username = c.get('username');
  const { encrypted_data, iv } = await c.req.json();
  if (!encrypted_data || !iv) return c.json({ error: "参数不完整" }, 400);
  
  await c.env.DB.prepare("INSERT INTO passwords (username, encrypted_data, iv) VALUES (?, ?, ?)").bind(username, encrypted_data, iv).run();
  return c.json({ success: true });
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
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>私人密码箱</title>
        <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔒</text></svg>">
        <style>
            :root { --primary: #0071e3; --bg: #f5f5f7; --card-bg: #ffffff; --text: #1d1d1f; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); max-width: 800px; margin: 0 auto; padding: 20px; }
            .card { background: var(--card-bg); padding: 30px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); margin-bottom: 20px; }
            h2, h3 { margin-top: 0; font-weight: 600; text-align: center; }
            input, select, button { padding: 12px 16px; margin: 8px 0; border: 1px solid #d2d2d7; border-radius: 8px; font-size: 15px; box-sizing: border-box; width: 100%; }
            button { background: var(--primary); color: white; border: none; cursor: pointer; font-weight: 600; transition: background 0.2s; }
            button:hover { background: #0077ed; }
            button.secondary { background: #e8e8ed; color: #1d1d1f; width: auto; }
            button.secondary:hover { background: #d2d2d7; }
            button.danger { background: #ff453a; width: auto; }
            button.danger:hover { background: #ff3b30; }
            .form-group { margin-bottom: 15px; }
            .form-group label { display: block; margin-bottom: 6px; font-size: 14px; font-weight: 500; color: #515154; }
            .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
            .secret-item { background: #fafafa; border: 1px solid #e5e5e7; border-radius: 10px; padding: 18px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #e2f6ea; color: #1a7f37; margin-bottom: 5px; }
            .copy-btn { padding: 5px 10px; font-size: 12px; margin-left: 5px; }
            .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .logo { font-size: 22px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
            .search-bar { padding: 12px; margin-bottom: 15px; border: 1px solid #d2d2d7; border-radius: 8px; font-size: 15px; }
            .generator-container { background: #fdfdfd; border: 1px dashed #d2d2d7; padding: 15px; border-radius: 8px; margin-top: 10px; }
            .generator-container input[type="checkbox"] { width: auto; margin-right: 5px; vertical-align: middle; }
            .generator-container label { font-size: 14px; margin-right: 15px; cursor: pointer; white-space: nowrap; }
            .generator-grid { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 8px; }
            .toggle-link { text-align: center; margin-top: 15px; font-size: 14px; color: var(--primary); cursor: pointer; text-decoration: underline; }
            .file-upload-label { display: inline-block; padding: 10px 16px; background: #e8e8ed; color: #1d1d1f; border-radius: 8px; cursor: pointer; font-size: 15px; font-weight: 600; transition: background 0.2s; text-align: center; margin: 8px 0; }
            .file-upload-label:hover { background: #d2d2d7; }
        </style>
    </head>
    <body>
        
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
            <!-- 【防呆设计】注册时才显示的确认密码框 -->
            <div class="form-group" id="confirmPasswordGroup" style="display: none;">
                <label>确认密码 (Confirm Password)</label>
                <input type="password" id="confirmPasswordInput" placeholder="请再次输入登录密码" onkeyup="if(event.key==='Enter') handleAuth()">
            </div>
            <button id="authBtn" onclick="handleAuth()" style="margin-top: 10px;">登 录</button>
            <div class="toggle-link" id="authToggle" onclick="toggleAuthMode()">没有账号？立即注册</div>
        </div>

        <div id="mainWorkspace" style="display: none;">
            <div class="header">
                <div class="logo">🔒 私人密码箱 <span style="font-size: 13px; color: #86868b; font-weight: normal;" id="currentUserLabel"></span></div>
                <button class="danger" onclick="logout()" style="padding: 6px 12px; font-size: 13px;">安全退出</button>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 10px;">💽 数据备份与恢复 (离线 JSON)</h3>
                <p style="font-size: 13px; color: #86868b; margin-bottom: 15px;">零知识架构下若遗忘密码数据将永久丢失。请务必定期导出未加密的 JSON 文件，存放在 U 盘等安全离线环境中。</p>
                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <button class="secondary" onclick="exportJSON()" style="margin: 0;">⬇️ 导出明文备份</button>
                    <label for="importFile" class="file-upload-label" style="margin: 0;">⬆️ 从备份恢复导入</label>
                    <input type="file" id="importFile" accept=".json" style="display: none;" onchange="importJSON(event)">
                </div>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 15px;">➕ 保存新账号密码</h3>
                <div class="grid">
                    <input type="text" id="site" placeholder="网站域名 (如 github.com)">
                    <input type="text" id="username" placeholder="账号 / 邮箱 / 手机号">
                </div>
                <div style="display: flex; gap: 10px; align-items: center;">
                    <input type="text" id="password" placeholder="密码明文" style="flex-grow: 1;">
                    <button class="secondary" onclick="toggleGenerator()" style="white-space: nowrap; margin:0;">生成器选项</button>
                </div>
                
                <!-- 【新增】安全备注字段 -->
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

                <button onclick="saveSecret()" style="margin-top: 15px;">加密并存入云端</button>
            </div>

            <div class="card">
                <!-- 【新增】提示模糊搜索支持备注 -->
                <h3 style="text-align: left; margin-bottom: 15px;">📋 已保存的凭证</h3>
                <input type="text" id="searchBar" class="search-bar" placeholder="🔍 搜索网站、账号名称或备注..." oninput="filterSecrets()">
                <div id="list"></div>
            </div>
        </div>

        <script>
            let cachedMasterKey = null; let cachedAuthKey = null; let cachedUsername = null;
            let dbSalt = null; let allDecryptedSecrets = []; let isRegisterMode = false;

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

            // 【UI更新】切换登录/注册模式时，显示或隐藏确认密码框
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

                // 【校验】如果是注册模式，必须验证两次密码一致
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
                allDecryptedSecrets = [];
                document.getElementById('passwordInput').value = '';
                document.getElementById('confirmPasswordInput').value = '';
                document.getElementById('usernameInput').value = '';
                document.getElementById('searchBar').value = '';
                
                isRegisterMode = false;
                document.getElementById('authTitle').innerText = "🔑 密码箱登录";
                document.getElementById('authBtn').innerText = "登 录";
                document.getElementById('authToggle').innerText = "没有账号？立即注册";
                document.getElementById('confirmPasswordGroup').style.display = "none";
                
                document.getElementById('authCard').style.display = "block";
                document.getElementById('mainWorkspace').style.display = "none";
                document.getElementById('generatorPanel').style.display = "none";
                document.getElementById('list').innerHTML = '';
            }

            async function saveSecret() {
                if (!cachedMasterKey || !cachedAuthKey) return alert("登录过期！");
                const site = document.getElementById('site').value.trim();
                const username = document.getElementById('username').value.trim();
                const password = document.getElementById('password').value;
                const note = document.getElementById('note').value.trim(); // 获取备注

                if (!site || !username || !password) return alert("网站名、账号和密码必填！");

                try {
                    const iv = window.crypto.getRandomValues(new Uint8Array(12));
                    const encoder = new TextEncoder();
                    // 【零知识升级】将 note 无缝打包进 JSON 黑盒
                    const payload = JSON.stringify({ site, username, password, note });
                    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cachedMasterKey, encoder.encode(payload));

                    const encrypted_data = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
                    const iv_str = btoa(String.fromCharCode(...iv));

                    const res = await fetch('/api/secrets', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey },
                        body: JSON.stringify({ encrypted_data, iv: iv_str })
                    });
                    
                    if (res.ok) {
                        document.getElementById('site').value = '';
                        document.getElementById('username').value = '';
                        document.getElementById('password').value = '';
                        document.getElementById('note').value = ''; // 清空备注框
                        await loadSecrets();
                    } else {
                        const err = await res.json();
                        alert("保存失败: " + err.error);
                    }
                } catch (e) {
                    alert("加密失败: " + e.message);
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
                        // 兼容老数据：如果没有 note 字段，默认为空字符串
                        allDecryptedSecrets.push({ 
                            id: item.id, 
                            site: credentials.site, 
                            username: credentials.username, 
                            password: credentials.password,
                            note: credentials.note || '' 
                        });
                    } catch (e) {}
                }
                renderSecrets(allDecryptedSecrets);
            }

            function renderSecrets(secrets) {
                const listDiv = document.getElementById('list');
                listDiv.innerHTML = '';
                if (secrets.length === 0) {
                    listDiv.innerHTML = '<p style="color:#86868b; text-align:center;">此账号箱子中暂无密码记录。</p>';
                    return;
                }
                secrets.forEach(item => {
                    // 【渲染更新】如果存在备注，则优雅地显示出来
                    const noteHtml = item.note ? \`<div style="margin: 8px 0 0; font-size: 13px; color:#515154; background: #f0f0f5; padding: 8px; border-radius: 6px;">📝 <strong>备注:</strong> \${escapeHtml(item.note)}</div>\` : '';
                    
                    listDiv.innerHTML += \`
                        <div class="secret-item">
                            <div style="flex-grow: 1;">
                                <span class="badge">已解密</span>
                                <strong style="font-size: 16px; display:block; color:#1d1d1f;">\${escapeHtml(item.site)}</strong>
                                <div style="margin: 6px 0 0; font-size: 14px; color:#515154;">
                                    账号: <span id="user-\${item.id}">\${escapeHtml(item.username)}</span>
                                    <button class="secondary copy-btn" onclick="copyToClipboard('user-\${item.id}')">复制</button>
                                </div>
                                <div style="margin: 4px 0 0; font-size: 14px; color:#515154;">
                                    密码: <span id="pwd-\${item.id}" style="-webkit-text-security: disc;">\${escapeHtml(item.password)}</span>
                                    <button class="secondary copy-btn" onclick="togglePasswordVisibility('pwd-\${item.id}', this)">显示</button>
                                    <button class="secondary copy-btn" onclick="copyToClipboard('pwd-\${item.id}')">复制</button>
                                </div>
                                \${noteHtml}
                            </div>
                            <button class="danger" onclick="deleteSecret(\${item.id})" style="padding:8px 12px; font-size:13px; margin-left: 15px; flex-shrink: 0;">删除</button>
                        </div>
                    \`;
                });
            }

            function filterSecrets() {
                const query = document.getElementById('searchBar').value.toLowerCase();
                // 【搜索增强】现在搜索词会同时匹配网站名、账号名和备注内容
                const filtered = allDecryptedSecrets.filter(item => 
                    item.site.toLowerCase().includes(query) || 
                    item.username.toLowerCase().includes(query) ||
                    item.note.toLowerCase().includes(query)
                );
                renderSecrets(filtered);
            }

            async function deleteSecret(id) {
                if (!cachedAuthKey) return;
                if (confirm("确定要永久删除这条记录吗？数据不可恢复！")) {
                    const res = await fetch('/api/secrets/' + id, { method: 'DELETE', headers: { 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey }});
                    if (res.ok) await loadSecrets();
                }
            }

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
                navigator.clipboard.writeText(document.getElementById(elementId).textContent).then(() => alert("已复制！"));
            }

            function escapeHtml(string) {
                return String(string).replace(/[&<>"']/g, function (s) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[s]; });
            }

            function exportJSON() {
                if (allDecryptedSecrets.length === 0) return alert("当前密码箱为空，没有需要导出的数据！");
                // 导出时加入 note
                const exportData = allDecryptedSecrets.map(item => ({ 
                    site: item.site, 
                    username: item.username, 
                    password: item.password,
                    note: item.note 
                }));
                const dataStr = JSON.stringify(exportData, null, 2);
                const blob = new Blob([dataStr], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = \`Vault_Backup_\${new Date().toISOString().split('T')[0]}.json\`;
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
                            // 导入时支持原有的 note
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
                        alert(\`✅ 导入完成！成功将 \${successCount} 条记录加密并存入当前账号。\`);
                        await loadSecrets(); 
                    } catch (err) {
                        alert("导入失败: 文件解析错误或网络异常 (" + err.message + ")");
                    } finally {
                        event.target.value = ''; document.getElementById('importFile').disabled = false;
                    }
                };
                reader.readAsText(file);
            }

            fetchMasterSalt();
        </script>
    </body>
    </html>
  `);
});

export default app;