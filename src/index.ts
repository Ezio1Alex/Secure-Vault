import { Hono, Context, Next } from 'hono';

type AppEnv = {
  Bindings: { DB: D1Database; };
  Variables: { username: string; };
};

const app = new Hono<AppEnv>();

function _t(c: Context, zh: string, en: string): string {
  return c.req.header('x-lang')?.startsWith('en') ? en : zh;
}

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
  if (!username || !auth_key) return c.json({ error: _t(c, "参数不完整", "Incomplete parameters") }, 400);

  try {
    const userCount = await c.env.DB.prepare("SELECT COUNT(*) as count FROM users").first() as { count: number } | null;
    if (userCount && userCount.count >= 5) {
      return c.json({ error: _t(c, "🚨 注册通道已关闭：当前私有密码箱已达到最大允许账号数 (5个)！", "🚨 Registration closed (max 5 accounts)") }, 403);
    }
    const cleanUsername = username.trim().toLowerCase();
    await c.env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").bind(cleanUsername, auth_key).run();
    return c.json({ success: true });
  } catch (err: any) {
    if (err.message && err.message.includes("UNIQUE")) return c.json({ error: _t(c, "该账号已被注册，请换一个用户名", "Username already taken") }, 400);
    return c.json({ error: _t(c, "注册失败", "Registration failed") + ": " + err.message }, 500);
  }
});

app.post('/api/login', async (c) => {
  const { username, auth_key } = await c.req.json();
  if (!username || !auth_key) return c.json({ error: _t(c, "参数不完整", "Incomplete parameters") }, 400);

  const cleanUsername = username.trim().toLowerCase();
  try {
    const user = await c.env.DB.prepare("SELECT password_hash FROM users WHERE username = ?").bind(cleanUsername).first() as { password_hash: string } | null;
    if (!user || user.password_hash !== auth_key) return c.json({ error: _t(c, "账号或密码错误", "Wrong username or password") }, 401);
    return c.json({ success: true });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

const authMiddleware = async (c: Context<AppEnv>, next: Next) => {
  const username = c.req.header('x-username');
  const authKey = c.req.header('x-auth-key');
  if (!username || !authKey) return c.json({ error: _t(c, "未授权的访问", "Unauthorized access") }, 401);

  const cleanUsername = username.trim().toLowerCase();
  const user = await c.env.DB.prepare("SELECT password_hash FROM users WHERE username = ?").bind(cleanUsername).first() as { password_hash: string } | null;
  if (!user || user.password_hash !== authKey) return c.json({ error: _t(c, "身份核验失败，请重新登录", "Auth verification failed, please log in again") }, 401);

  c.set('username', cleanUsername);
  await next();
};

app.get('/api/secrets', authMiddleware, async (c) => {
  const username = c.get('username');
  try {
    const { results } = await c.env.DB.prepare("SELECT id, encrypted_data, iv, updated_at, pinned FROM passwords WHERE username = ? ORDER BY pinned DESC, id DESC").bind(username).all();
    return c.json(results);
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

app.post('/api/secrets', authMiddleware, async (c) => {
  const username = c.get('username');
  const { encrypted_data, iv } = await c.req.json();
  if (!encrypted_data || !iv) return c.json({ error: _t(c, "参数不完整", "Incomplete parameters") }, 400);

  await c.env.DB.prepare("INSERT INTO passwords (username, encrypted_data, iv, updated_at, pinned) VALUES (?, ?, ?, CURRENT_TIMESTAMP, 0)").bind(username, encrypted_data, iv).run();
  return c.json({ success: true });
});

app.put('/api/secrets/:id', authMiddleware, async (c) => {
  const id = c.req.param('id');
  const username = c.get('username');
  const { encrypted_data, iv, touch_timestamp } = await c.req.json();
  if (!encrypted_data || !iv) return c.json({ error: _t(c, "参数不完整", "Incomplete parameters") }, 400);

  try {
    const sql = touch_timestamp === false
      ? "UPDATE passwords SET encrypted_data = ?, iv = ? WHERE id = ? AND username = ?"
      : "UPDATE passwords SET encrypted_data = ?, iv = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND username = ?";
    const result = await c.env.DB.prepare(sql).bind(encrypted_data, iv, id, username).run();
    if (result.meta.changes === 0) return c.json({ error: _t(c, "记录不存在或无权修改", "Record not found or no permission") }, 404);
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

app.post('/api/secrets/:id/pin', authMiddleware, async (c) => {
  const id = c.req.param('id');
  const username = c.get('username');
  try {
    await c.env.DB.prepare("UPDATE passwords SET pinned = 1 - pinned WHERE id = ? AND username = ?").bind(id, username).run();
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
        <title data-i18n="app.title">私人密码箱</title>
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
            .secret-item { background: var(--item-bg); border: 1px solid var(--item-border); border-radius: 10px; padding: 18px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: flex-start; transition: background 0.3s; }
            .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #e2f6ea; color: #1a7f37; }
            .copy-btn { padding: 5px 10px; font-size: 12px; margin-left: 5px; }
            .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .logo { font-size: 22px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
            .search-bar { padding: 12px; margin-bottom: 15px; border: 1px solid var(--border); border-radius: 8px; font-size: 15px; width: 100%; box-sizing: border-box; background: var(--card-bg); color: var(--text); }
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
            /* 置顶 */
            .pin-btn-top { background: none; border: none; cursor: pointer; font-size: 14px; padding: 4px; margin: 0; width: auto; line-height: 1; position: absolute; top: 4px; right: 4px; z-index: 1; }
            .pin-btn-top:hover { background: var(--secondary-bg); border-radius: 4px; }
            .item-actions { display: flex; flex-direction: column; gap: 6px; flex-shrink: 0; margin-left: 15px; padding-top: 26px; }
            /* 分组 */
            .group-header { background: #fef3c7; color: #92400e; padding: 12px 16px; border-radius: 10px; margin-bottom: 8px; cursor: pointer; font-size: 15px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; user-select: none; transition: background 0.2s; border: 1px solid #fde68a; }
            .group-header:hover { background: #fde68a; }
            .group-header .count { font-size: 13px; opacity: 0.85; }
            .group-body { margin-left: 8px; padding-left: 12px; border-left: 2px solid var(--border); margin-bottom: 12px; }
            /* 移动端适配 */
            @media (max-width: 640px) {
                body { padding: 10px; }
                .card { padding: 16px; border-radius: 12px; }
                .logo { font-size: 17px; }
                .sort-bar { flex-wrap: wrap; gap: 6px; }
                .sort-bar > select { width: auto; flex: 1; min-width: 0; font-size: 13px; padding: 8px; }
                .sort-bar > div { width: 100%; order: 3; }
                .group-header { font-size: 14px; padding: 10px 12px; }
                .secret-item { flex-direction: column; gap: 10px; }
                .item-actions { flex-direction: row; margin-left: 0; width: 100%; gap: 8px; padding-top: 0; }
                .item-actions button { flex: 1; padding: 10px !important; font-size: 13px !important; text-align: center; }
                .copy-btn { padding: 6px 10px; font-size: 13px; min-width: 44px; min-height: 36px; }
                .group-body { margin-left: 0; padding-left: 8px; }
                #authCard { margin: 40px auto 0 !important; }
                .header { flex-wrap: wrap; gap: 8px; }
                .header .danger { font-size: 12px !important; padding: 6px 10px !important; }
                #togglePwdBtn, #genSettingsBtn, [onclick="generatePassword()"] { min-width: 44px; min-height: 44px; font-size: 16px !important; padding: 10px 12px !important; }
                .sort-bar > div:first-of-type { width: auto; display: inline-flex; }
            }
        </style>
    </head>
    <body>

        <div id="lockWarning" class="lock-warning">⏰ 30 秒后因闲置自动锁定</div>

        <div class="card" id="authCard" style="max-width: 400px; margin: 80px auto 0; position: relative;">
            <button id="langToggleAuth" onclick="switchLanguage(currentLang === 'zh' ? 'en' : 'zh')" style="position:absolute;top:12px;right:16px;padding:3px 8px;font-size:11px;font-weight:600;line-height:1;margin:0;width:auto;white-space:nowrap;background:var(--secondary-bg);color:var(--text-secondary);border:1px solid var(--border);border-radius:6px;cursor:pointer;">EN</button>
            <button id="themeToggleAuth" onclick="toggleTheme()" style="position:absolute;top:12px;right:56px;padding:3px 8px;font-size:11px;line-height:1;margin:0;width:auto;background:var(--secondary-bg);color:var(--text-secondary);border:1px solid var(--border);border-radius:6px;cursor:pointer;">🌙</button>
            <h2 id="authTitle">🔑 密码箱登录</h2>
            <div class="form-group">
                <label data-i18n="auth.label.username">登录账号 (Username)</label>
                <input type="text" id="usernameInput" data-i18n-placeholder="auth.placeholder.username" placeholder="输入你的账号名称">
            </div>
            <div class="form-group">
                <label data-i18n="auth.label.password">登录密码 (Master Password)</label>
                <input type="password" id="passwordInput" data-i18n-placeholder="auth.placeholder.password" placeholder="输入登录密码" onkeyup="if(event.key==='Enter') handleAuth()">
            </div>
            <div class="form-group" id="confirmPasswordGroup" style="display: none;">
                <label data-i18n="auth.label.confirm">确认密码 (Confirm Password)</label>
                <input type="password" id="confirmPasswordInput" data-i18n-placeholder="auth.placeholder.confirm" placeholder="请再次输入登录密码" onkeyup="if(event.key==='Enter') handleAuth()">
            </div>
            <button id="authBtn" onclick="handleAuth()" style="margin-top: 10px;">登 录</button>
            <div class="toggle-link" id="authToggle" onclick="toggleAuthMode()">没有账号？立即注册</div>
        </div>

        <div id="mainWorkspace" style="display: none;">
            <div class="header">
                <div class="logo"><span data-i18n="app.logo">🔒 私人密码箱</span> <span style="font-size: 13px; color: var(--text-secondary); font-weight: normal;" id="currentUserLabel"></span></div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" data-i18n-title="header.theme" title="切换深色模式" style="padding: 6px 10px; font-size: 14px; line-height: 1; margin: 0; width: auto;">🌙</button>
                    <button id="langToggle" onclick="switchLanguage(currentLang === 'zh' ? 'en' : 'zh')" style="padding:6px 10px;font-size:12px;font-weight:600;line-height:1;margin:0;width:auto;white-space:nowrap;background:var(--secondary-bg);color:var(--text);border:1px solid var(--border);border-radius:8px;cursor:pointer;">EN</button>
                    <button class="danger" data-i18n="header.logout" onclick="logout()" style="padding: 6px 10px; font-size: 12px; line-height: 1; margin: 0;">安全退出</button>
                </div>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 10px;" data-i18n="backup.title">💽 数据备份与恢复 (离线 JSON)</h3>
                <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 15px;" data-i18n="backup.desc">零知识架构下若遗忘密码数据将永久丢失。请务必定期导出未加密的 JSON 文件，存放在 U 盘等安全离线环境中。</p>
                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <button class="secondary" data-i18n="backup.export" onclick="exportJSON()" style="margin: 0;">⬇️ 导出明文备份</button>
                    <label for="importFile" class="file-upload-label" data-i18n="backup.import" style="margin: 0;">⬆️ 从备份恢复导入</label>
                    <input type="file" id="importFile" accept=".json" style="display: none;" onchange="importJSON(event)">
                </div>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 15px;" id="saveFormTitle">➕ 保存新账号密码</h3>
                <!-- 网站 -->
                <div style="margin-bottom: 12px;">
                    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 4px;" data-i18n="form.label.site">网站</div>
                    <input type="text" id="site" data-i18n-placeholder="form.placeholder.site" placeholder="如 github.com" style="margin: 0;">
                </div>
                <!-- 账号 -->
                <div style="margin-bottom: 12px;">
                    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 4px;" data-i18n="form.label.account">账号</div>
                    <input type="text" id="editUsername" data-i18n-placeholder="form.placeholder.account" placeholder="邮箱 / 手机号 / 用户名" style="margin: 0;">
                </div>
                <!-- 密码 -->
                <div style="margin-bottom: 12px;">
                    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 4px;" data-i18n="form.label.password">密码</div>
                    <div style="display: flex; gap: 6px; align-items: center;">
                        <input type="text" id="password" data-i18n-placeholder="form.placeholder.password" placeholder="密码明文或点击生成" style="flex-grow: 1; margin: 0;">
                        <button class="secondary" id="togglePwdBtn" onclick="togglePwdVisibility()" data-i18n-title="form.hidePwd" title="隐藏密码" style="padding: 10px 12px; margin: 0; width: auto; white-space: nowrap;">🙈</button>
                        <button class="secondary" onclick="generatePassword()" data-i18n-title="form.genPwd" title="一键生成密码" style="padding: 10px 12px; margin: 0; width: auto; white-space: nowrap;">🔑</button>
                        <button class="secondary" id="genSettingsBtn" onclick="toggleGenSettings()" data-i18n-title="form.genSettings" title="生成器设置" style="padding: 10px 12px; margin: 0; width: auto; white-space: nowrap;">⚙</button>
                    </div>
                    <div id="strengthIndicator" style="display: none; margin-top: 4px;">
                        <div class="strength-bar" id="strengthBar" style="width: 0%; background: transparent;"></div>
                        <div class="strength-label" id="strengthLabel"></div>
                    </div>
                    <!-- 生成器设置（默认收起，放在密码下面） -->
                    <div id="genSettingsPanel" style="display: none; margin-top: 8px; padding: 10px 12px; background: var(--item-bg); border-radius: 8px; border: 1px solid var(--border);">
                        <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap; font-size: 13px;">
                            <span data-i18n="form.label.length">长度 <input type="number" id="genLength" value="16" min="6" max="64" style="width: 48px; padding: 4px 6px; margin: 0; display: inline-block;"></span>
                            <label style="display: inline-flex; align-items: center; gap: 3px; cursor: pointer; margin: 0;"><input type="checkbox" id="genUpper" checked style="width: auto; margin: 0;">A-Z</label>
                            <label style="display: inline-flex; align-items: center; gap: 3px; cursor: pointer; margin: 0;"><input type="checkbox" id="genLower" checked style="width: auto; margin: 0;">a-z</label>
                            <label style="display: inline-flex; align-items: center; gap: 3px; cursor: pointer; margin: 0;"><input type="checkbox" id="genNumber" checked style="width: auto; margin: 0;">0-9</label>
                            <label style="display: inline-flex; align-items: center; gap: 3px; cursor: pointer; margin: 0;"><input type="checkbox" id="genSymbols" checked style="width: auto; margin: 0;">@#$</label>
                        </div>
                    </div>
                </div>
                <!-- 备注 -->
                <div style="margin-bottom: 12px;">
                    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 4px;" data-i18n="form.label.note">备注</div>
                    <textarea id="note" rows="1" data-i18n-placeholder="form.placeholder.note" placeholder="选填，如安全问题答案、绑定的手机号等" oninput="autoResize(this)" style="margin:0;padding:10px 12px;border:1px solid var(--border);border-radius:8px;font-size:15px;color:var(--text);background:var(--card-bg);resize:none;width:100%;box-sizing:border-box;font-family:inherit;line-height:1.5;overflow-y:auto;min-height:44px;max-height:120px;" onfocus="this.style.borderColor='var(--primary)'" onblur="this.style.borderColor='var(--border)'"></textarea>
                </div>
                <!-- 按钮 -->
                <div style="display: flex; gap: 10px;">
                    <button onclick="saveSecret()" style="margin-top: 4px; flex-grow: 1;" id="saveBtn">加密并存入云端</button>
                    <button class="secondary" onclick="cancelEdit()" id="cancelEditBtn" style="margin-top: 4px; display: none;">取消编辑</button>
                </div>
            </div>

            <div class="card">
                <h3 style="text-align: left; margin-bottom: 15px;" data-i18n="list.title">📋 已保存的凭证</h3>
                <div class="sort-bar">
                    <label data-i18n="list.sort">排序：</label>
                    <div style="position: relative; width: auto;">
                        <div id="sortDisplay" onclick="toggleSortDropdown(event)" style="padding:8px 12px;border:1px solid var(--border);border-radius:8px;font-size:14px;color:var(--text);background:var(--card-bg);cursor:pointer;display:flex;align-items:center;gap:4px;user-select:none;white-space:nowrap;height:100%;box-sizing:border-box;">
                            <span id="sortLabel" data-i18n="list.sort.newest">最近添加</span> <span style="font-size:10px;">▾</span>
                        </div>
                        <select id="sortSelect" onchange="onSortChange()" style="display: none;">
                            <option value="newest">最近添加</option>
                            <option value="oldest">最早添加</option>
                            <option value="updated">最近更新</option>
                            <option value="most">账号最多</option>
                        </select>
                        <div id="sortDropdownPanel" style="display:none;position:absolute;top:100%;left:0;min-width:140px;background:var(--card-bg);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.12);z-index:1000;margin-top:4px;padding:4px 0;"></div>
                    </div>
                    <div style="display: flex; flex-grow: 1; border: 1px solid var(--border); border-radius: 8px; overflow: visible; margin: 0; background: var(--card-bg); position: relative;">
                        <div id="siteFilterDisplay" onclick="toggleSiteDropdown(event)" style="padding: 8px 12px; white-space: nowrap; cursor: pointer; font-size: 14px; border-right: 1px solid var(--border); display: flex; align-items: center; gap: 4px; user-select: none; background: var(--card-bg); color: var(--text); border-radius: 8px 0 0 8px;">
                            <span id="siteFilterLabel" data-i18n="list.filter.all">全部网站</span> <span style="font-size: 10px;">▾</span>
                        </div>
                        <select id="siteFilter" onchange="filterSecrets()" style="display: none;">
                            <option value="">全部网站</option>
                        </select>
                        <!-- 自定义下拉面板 -->
                        <div id="siteDropdownPanel" style="display: none; position: absolute; top: 100%; left: 0; min-width: 180px; max-height: 250px; overflow-y: auto; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.12); z-index: 1000; margin-top: 4px; padding: 4px 0;"></div>
                        <input type="text" id="searchBar" class="search-bar" data-i18n-placeholder="list.search" placeholder="🔍 搜索账号或备注..." oninput="filterSecrets()" style="margin: 0 !important; flex-grow: 1; border: none !important; padding: 8px 12px !important; border-radius: 0 !important;">
                    </div>
                </div>
                <div id="list"></div>
            </div>
        </div>

        <script>
            let cachedMasterKey = null; let cachedAuthKey = null; let cachedUsername = null;
            let dbSalt = null; let allDecryptedSecrets = []; let isRegisterMode = false;
            let editTargetId = null; /* 正在编辑的记录 id */
            let editOriginalPassword = null; /* 编辑前的密码，用于判断是否更新时间戳 */

            /* ====== 客户端国际化 i18n ====== */
            const LANG = {
              zh: {
                'app.title': '私人密码箱',
                'app.logo': '🔒 私人密码箱',
                'lang.name': '中文',
                'lang.toggle': 'EN',

                'lock.warning': '⏰ {s} 秒后因闲置自动锁定',
                'lock.auto': '已自动锁定，请重新登录',

                'auth.loginTitle': '🔑 密码箱登录',
                'auth.registerTitle': '📝 注册新账号',
                'auth.loginBtn': '登 录',
                'auth.registerBtn': '注 册 并 登 录',
                'auth.label.username': '登录账号 (Username)',
                'auth.placeholder.username': '输入你的账号名称',
                'auth.label.password': '登录密码 (Master Password)',
                'auth.placeholder.password': '输入登录密码',
                'auth.label.confirm': '确认密码 (Confirm Password)',
                'auth.placeholder.confirm': '请再次输入登录密码',
                'auth.toggle.toLogin': '已有账号？立即登录',
                'auth.toggle.toRegister': '没有账号？立即注册',
                'auth.computing': '计算安全密钥中...',
                'auth.error.empty': '账号和密码不能为空！',
                'auth.error.confirmMismatch': '两次输入的密码不一致，请重新检查！',
                'auth.error.registerFailed': '注册失败！',
                'auth.success.register': '🎉 注册成功！',
                'auth.error.loginFailed': '账号或密码错误！',
                'auth.error.network': '网络错误: {msg}',

                'header.logout': '安全退出',
                'header.theme': '切换深色模式',

                'backup.title': '💽 数据备份与恢复 (离线 JSON)',
                'backup.desc': '零知识架构下若遗忘密码数据将永久丢失。请务必定期导出未加密的 JSON 文件，存放在 U 盘等安全离线环境中。',
                'backup.export': '⬇️ 导出明文备份',
                'backup.import': '⬆️ 从备份恢复导入',

                'form.title.new': '➕ 保存新账号密码',
                'form.title.edit': '✏️ 编辑密码',
                'form.save': '加密并存入云端',
                'form.update': '更新并保存',
                'form.cancel': '取消编辑',
                'form.label.site': '网站',
                'form.placeholder.site': '如 github.com',
                'form.label.account': '账号',
                'form.placeholder.account': '邮箱 / 手机号 / 用户名',
                'form.label.password': '密码',
                'form.placeholder.password': '密码明文或点击生成',
                'form.hidePwd': '隐藏密码',
                'form.genPwd': '一键生成密码',
                'form.genSettings': '生成器设置',
                'form.label.length': '长度',
                'form.label.note': '备注',
                'form.placeholder.note': '选填，如安全问题答案、绑定的手机号等',
                'form.error.empty': '网站名、账号和密码必填！',
                'form.error.expired': '登录过期！',
                'form.error.saveFailed': '保存失败: {msg}',
                'form.error.genCharset': '请至少选择一种字符集！',

                'list.title': '📋 已保存的凭证',
                'list.empty': '此账号箱子中暂无密码记录。',
                'list.sort': '排序：',
                'list.sort.newest': '最近添加',
                'list.sort.oldest': '最早添加',
                'list.sort.updated': '最近更新',
                'list.sort.most': '账号最多',
                'list.filter.all': '全部网站',
                'list.search': '🔍 搜索账号或备注...',
                'list.accounts': '{n} 个账号',
                'list.copy': '复制',
                'list.open': '打开',
                'list.copy.site': '网址已复制',
                'list.label.account': '账号: ',
                'list.label.password': '密码: ',
                'list.btn.show': '显示',
                'list.btn.hide': '隐藏',
                'list.copied': '已复制',
                'list.copied.account': '账号已复制',
                'list.copied.password': '密码已复制',
                'list.btn.edit': '✏️ 编辑',
                'list.btn.delete': '删除',
                'list.pin.on': '取消置顶',
                'list.pin.off': '置顶',

                'confirm.delete': '确定要永久删除这条记录吗？数据不可恢复！',

                'export.empty': '当前密码箱为空，没有需要导出的数据！',

                'import.confirm': '导入操作将会把 JSON 备份文件中的密码逐条加密上传至云端，确定执行吗？\\n(建议在全新的空账号中执行导入，避免数据重复)',
                'import.error.format': 'JSON 格式错误，应为一个数组格式',
                'import.success': '✅ 导入完成！成功将 {n} 条记录加密并存入当前账号。',
                'import.error.failed': '导入失败: 文件解析错误或网络异常 ({msg})',

                'strength.label': '密码强度：',
                'strength.weak': '弱',
                'strength.medium': '中',
                'strength.strong': '强',

                'time.justNow': '刚刚',
                'time.minutesAgo': '{n} 分钟前',
                'time.hoursAgo': '{n} 小时前',
                'time.daysAgo': '{n} 天前',
                'time.monthsAgo': '{n} 个月前',
              },
              en: {
                'app.title': 'Secure Vault',
                'app.logo': '🔒 Secure Vault',
                'lang.name': 'English',
                'lang.toggle': '中',

                'lock.warning': '⏰ Auto-lock in {s} seconds',
                'lock.auto': 'Auto-locked due to inactivity',

                'auth.loginTitle': '🔑 Vault Login',
                'auth.registerTitle': '📝 Create Account',
                'auth.loginBtn': 'Log In',
                'auth.registerBtn': 'Register & Log In',
                'auth.label.username': 'Username',
                'auth.placeholder.username': 'Enter your username',
                'auth.label.password': 'Master Password',
                'auth.placeholder.password': 'Enter your master password',
                'auth.label.confirm': 'Confirm Password',
                'auth.placeholder.confirm': 'Re-enter your master password',
                'auth.toggle.toLogin': 'Already have an account? Log In',
                'auth.toggle.toRegister': "Don't have an account? Register",
                'auth.computing': 'Computing security keys...',
                'auth.error.empty': 'Username and password are required!',
                'auth.error.confirmMismatch': 'Passwords do not match!',
                'auth.error.registerFailed': 'Registration failed!',
                'auth.success.register': '🎉 Registration successful!',
                'auth.error.loginFailed': 'Wrong username or password!',
                'auth.error.network': 'Network error: {msg}',

                'header.logout': 'Logout',
                'header.theme': 'Toggle dark mode',

                'backup.title': '💽 Backup & Restore (Offline JSON)',
                'backup.desc': 'In a zero-knowledge architecture, lost passwords mean permanent data loss. Please regularly export your plaintext JSON backup to a secure offline location (e.g. USB drive).',
                'backup.export': '⬇️ Export Plaintext Backup',
                'backup.import': '⬆️ Restore from Backup',

                'form.title.new': '➕ Save New Credential',
                'form.title.edit': '✏️ Edit Credential',
                'form.save': 'Encrypt & Save to Cloud',
                'form.update': 'Update & Save',
                'form.cancel': 'Cancel Edit',
                'form.label.site': 'Website',
                'form.placeholder.site': 'e.g. github.com',
                'form.label.account': 'Account',
                'form.placeholder.account': 'Email / Phone / Username',
                'form.label.password': 'Password',
                'form.placeholder.password': 'Plaintext password or generate',
                'form.hidePwd': 'Hide password',
                'form.genPwd': 'Generate password',
                'form.genSettings': 'Generator settings',
                'form.label.length': 'Length',
                'form.label.note': 'Note',
                'form.placeholder.note': 'Optional — security answers, linked phone, etc.',
                'form.error.empty': 'Website, account and password are required!',
                'form.error.expired': 'Session expired!',
                'form.error.saveFailed': 'Save failed: {msg}',
                'form.error.genCharset': 'Please select at least one character set!',

                'list.title': '📋 Saved Credentials',
                'list.empty': 'No credentials in this vault.',
                'list.sort': 'Sort: ',
                'list.sort.newest': 'Newest first',
                'list.sort.oldest': 'Oldest first',
                'list.sort.updated': 'Recently updated',
                'list.sort.most': 'Most accounts',
                'list.filter.all': 'All sites',
                'list.search': '🔍 Search account or note...',
                'list.accounts': '{n} account(s)',
                'list.copy': 'Copy',
                'list.open': 'Open',
                'list.copy.site': 'URL copied',
                'list.label.account': 'Account: ',
                'list.label.password': 'Password: ',
                'list.btn.show': 'Show',
                'list.btn.hide': 'Hide',
                'list.copied': 'Copied',
                'list.copied.account': 'Account copied',
                'list.copied.password': 'Password copied',
                'list.btn.edit': '✏️ Edit',
                'list.btn.delete': 'Delete',
                'list.pin.on': 'Unpin',
                'list.pin.off': 'Pin',

                'confirm.delete': 'Permanently delete this record? This cannot be undone!',

                'export.empty': 'Your vault is empty — nothing to export.',

                'import.confirm': 'This will encrypt and upload each entry from the JSON backup. Proceed?\\n(Recommended for fresh vaults to avoid duplicates)',
                'import.error.format': 'Invalid JSON format — expected an array.',
                'import.success': '✅ Import complete! {n} entries encrypted and saved.',
                'import.error.failed': 'Import failed: {msg}',

                'strength.label': 'Password strength: ',
                'strength.weak': 'Weak',
                'strength.medium': 'Medium',
                'strength.strong': 'Strong',

                'time.justNow': 'just now',
                'time.minutesAgo': '{n} min ago',
                'time.hoursAgo': '{n} hr ago',
                'time.daysAgo': '{n} day(s) ago',
                'time.monthsAgo': '{n} month(s) ago',
              },
            };

            let currentLang = 'zh';

            function t(key, vars) {
              var text = (LANG[currentLang] && LANG[currentLang][key]) || (LANG.zh[key] || key);
              if (vars) {
                for (var k in vars) {
                  text = text.replace('{' + k + '}', vars[k]);
                }
              }
              return text;
            }

            function switchLanguage(lang) {
              currentLang = lang;
              localStorage.setItem('vault-lang', lang);
              document.documentElement.lang = lang === 'en' ? 'en' : 'zh-CN';
              applyLanguage();
            }

            function applyLanguage() {
              /* data-i18n: textContent */
              var els = document.querySelectorAll('[data-i18n]');
              for (var i = 0; i < els.length; i++) {
                var key = els[i].getAttribute('data-i18n');
                if (key) els[i].textContent = t(key);
              }
              /* data-i18n-placeholder: placeholder */
              var inputs = document.querySelectorAll('[data-i18n-placeholder]');
              for (var j = 0; j < inputs.length; j++) {
                var pk = inputs[j].getAttribute('data-i18n-placeholder');
                if (pk) inputs[j].placeholder = t(pk);
              }
              /* data-i18n-title: title */
              var titles = document.querySelectorAll('[data-i18n-title]');
              for (var k = 0; k < titles.length; k++) {
                var tk = titles[k].getAttribute('data-i18n-title');
                if (tk) titles[k].title = t(tk);
              }
              /* language toggle buttons */
              var langBtn = document.getElementById('langToggle');
              if (langBtn) langBtn.textContent = t('lang.toggle');
              var langBtnAuth = document.getElementById('langToggleAuth');
              if (langBtnAuth) langBtnAuth.textContent = t('lang.toggle');
              /* 重新构建排序下拉 */
              initSortDropdown();
              /* 动态管理的按钮文本 */
              if (editTargetId) {
                document.getElementById('saveFormTitle').textContent = t('form.title.edit');
                document.getElementById('saveBtn').textContent = t('form.update');
              } else {
                document.getElementById('saveFormTitle').textContent = t('form.title.new');
                document.getElementById('saveBtn').textContent = t('form.save');
              }
              document.getElementById('cancelEditBtn').textContent = t('form.cancel');
              document.getElementById('authTitle').innerText = isRegisterMode ? t('auth.registerTitle') : t('auth.loginTitle');
              document.getElementById('authBtn').innerText = isRegisterMode ? t('auth.registerBtn') : t('auth.loginBtn');
              document.getElementById('authToggle').innerText = isRegisterMode ? t('auth.toggle.toLogin') : t('auth.toggle.toRegister');
            }

            /* 初始化语言：localStorage > 浏览器偏好 > 中文 */
            (function initLang() {
              try {
                var saved = localStorage.getItem('vault-lang');
                if (saved) {
                  currentLang = saved;
                } else {
                  var navLang = (navigator.language || '').split('-')[0];
                  currentLang = navLang === 'en' ? 'en' : 'zh';
                }
                document.documentElement.lang = currentLang === 'en' ? 'en' : 'zh-CN';
              } catch (e) {
                currentLang = 'zh';
              }
              try { applyLanguage(); } catch(e) { /* 语言切换失败不阻塞页面 */ }
            })();

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
                        warningEl.textContent = t('lock.warning', {s: remaining});
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
                document.getElementById('usernameInput').value = '';
                document.getElementById('mainWorkspace').style.display = 'none';
                document.getElementById('authCard').style.display = 'block';
                document.getElementById('list').innerHTML = '';
                if (lockCheckTimer) clearTimeout(lockCheckTimer);
                alert(t('lock.auto'));
            }

            /* ====== 深色模式 ====== */
            function getPreferredTheme() {
                return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }

            function applyTheme(theme) {
                document.documentElement.setAttribute('data-theme', theme);
                var icon = theme === 'dark' ? '☀️' : '🌙';
                document.getElementById('themeToggle').textContent = icon;
                var ta = document.getElementById('themeToggleAuth');
                if (ta) ta.textContent = icon;
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

                if (len >= 12 && types >= 3) return { level: 3, label: 'strong', width: 75, cls: 'strength-strong' };
                if (len >= 8 && types >= 2) return { level: 2, label: 'medium', width: 50, cls: 'strength-medium' };
                return { level: 1, label: 'weak', width: 25, cls: 'strength-weak' };
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
                    'weak': 'var(--strength-weak)',
                    'medium': 'var(--strength-medium)',
                    'strong': 'var(--strength-strong)'
                };
                bar.style.background = colorMap[result.label] || 'transparent';
                label.textContent = t('strength.label') + t('strength.' + result.label);
                label.className = 'strength-label ' + result.cls;
            }

            /* ====== 相对时间 ====== */
            function timeAgo(dateStr) {
                if (!dateStr) return '';
                var now = new Date();
                var date = new Date(dateStr + 'Z'); /* D1 返回的是 UTC，补 Z */
                var diff = Math.floor((now - date) / 1000);
                if (diff < 60) return t('time.justNow');
                if (diff < 3600) return t('time.minutesAgo', {n: Math.floor(diff / 60)});
                if (diff < 86400) return t('time.hoursAgo', {n: Math.floor(diff / 3600)});
                if (diff < 2592000) return t('time.daysAgo', {n: Math.floor(diff / 86400)});
                return t('time.monthsAgo', {n: Math.floor(diff / 2592000)});
            }

            /* ====== 登录 / 注册 ====== */
            function toggleAuthMode() {
                isRegisterMode = !isRegisterMode;
                document.getElementById('authTitle').innerText = isRegisterMode ? t('auth.registerTitle') : t('auth.loginTitle');
                document.getElementById('authBtn').innerText = isRegisterMode ? t('auth.registerBtn') : t('auth.loginBtn');
                document.getElementById('authToggle').innerText = isRegisterMode ? t('auth.toggle.toLogin') : t('auth.toggle.toRegister');
                document.getElementById('confirmPasswordGroup').style.display = isRegisterMode ? "block" : "none";
            }

            async function handleAuth() {
                const username = document.getElementById('usernameInput').value.trim();
                const password = document.getElementById('passwordInput').value;

                if (!username || !password) return alert(t('auth.error.empty'));

                if (isRegisterMode) {
                    const confirmPassword = document.getElementById('confirmPasswordInput').value;
                    if (password !== confirmPassword) {
                        return alert(t('auth.error.confirmMismatch'));
                    }
                }

                try {
                    if (!dbSalt) await fetchMasterSalt();
                    document.getElementById('authBtn').innerText = t('auth.computing');

                    setTimeout(async () => {
                        try {
                            const authKey = await deriveAuthKey(username, password, dbSalt);
                            const masterKey = await deriveKey(password, dbSalt);

                            if (isRegisterMode) {
                                const res = await fetch('/api/register', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json', 'x-lang': currentLang },
                                    body: JSON.stringify({ username, auth_key: authKey })
                                });
                                const data = await res.json();
                                if (!res.ok) throw new Error(data.error || t('auth.error.registerFailed'));
                                alert(t('auth.success.register'));
                            } else {
                                const res = await fetch('/api/login', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json', 'x-lang': currentLang },
                                    body: JSON.stringify({ username, auth_key: authKey })
                                });
                                const data = await res.json();
                                if (!res.ok) throw new Error(data.error || t('auth.error.loginFailed'));
                            }

                            cachedUsername = username; cachedAuthKey = authKey; cachedMasterKey = masterKey;
                            document.getElementById('authCard').style.display = "none";
                            document.getElementById('mainWorkspace').style.display = "block";
                            document.getElementById('currentUserLabel').innerText = "@" + username;
                            /* 登录成功后清除密码输入 */
                            document.getElementById('passwordInput').value = '';
                            document.getElementById('confirmPasswordInput').value = '';

                            resetActivity();
                            startLockTimer();
                            applyLanguage(); /* 刷新当前语言 */
                            await loadSecrets();
                        } catch (err) {
                            alert(err.message);
                        } finally {
                            document.getElementById('authBtn').innerText = isRegisterMode ? t('auth.registerBtn') : t('auth.loginBtn');
                        }
                    }, 50);
                } catch (e) {
                    alert(t('auth.error.network', {msg: e.message}));
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
                document.getElementById('authTitle').innerText = t('auth.loginTitle');
                document.getElementById('authBtn').innerText = t('auth.loginBtn');
                document.getElementById('authToggle').innerText = t('auth.toggle.toRegister');
                document.getElementById('confirmPasswordGroup').style.display = "none";

                document.getElementById('authCard').style.display = "block";
                document.getElementById('mainWorkspace').style.display = "none";
                document.getElementById('genSettingsPanel').style.display = "none";
                document.getElementById('list').innerHTML = '';
                cancelEdit();
            }

            /* ====== 保存 / 编辑 ====== */
            function cancelEdit() {
                editTargetId = null;
                editOriginalPassword = null;
                document.getElementById('saveFormTitle').textContent = t('form.title.new');
                document.getElementById('saveBtn').textContent = t('form.save');
                document.getElementById('saveBtn').style.background = '';
                document.getElementById('cancelEditBtn').style.display = 'none';
                document.getElementById('site').value = '';
                document.getElementById('editUsername').value = '';
                document.getElementById('password').value = '';
                document.getElementById('password').type = 'text';
                document.getElementById('togglePwdBtn').textContent = '🙈';
                document.getElementById('note').value = '';
document.getElementById('note').style.height = '44px';
                updateStrengthIndicator();
            }

            async function saveSecret() {
                if (!cachedMasterKey || !cachedAuthKey) return alert(t('form.error.expired'));
                const site = document.getElementById('site').value.trim();
                const username = document.getElementById('editUsername').value.trim();
                const password = document.getElementById('password').value;
                const note = document.getElementById('note').value.trim();

                if (!site || !username || !password) return alert(t('form.error.empty'));

                try {
                    const iv = window.crypto.getRandomValues(new Uint8Array(12));
                    const encoder = new TextEncoder();
                    const payload = JSON.stringify({ site, username, password, note });
                    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cachedMasterKey, encoder.encode(payload));

                    const encrypted_data = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
                    const iv_str = btoa(String.fromCharCode(...iv));

                    if (editTargetId) {
                        /* 更新已有记录：密码没变则不更新时间戳 */
                        const res = await fetch('/api/secrets/' + editTargetId, {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json', 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey, 'x-lang': currentLang },
                            body: JSON.stringify({ encrypted_data, iv: iv_str, touch_timestamp: password === editOriginalPassword ? false : undefined })
                        });
                        if (!res.ok) { const err = await res.json(); throw new Error(err.error); }
                        cancelEdit();
                    } else {
                        /* 新增 */
                        const res = await fetch('/api/secrets', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey, 'x-lang': currentLang },
                            body: JSON.stringify({ encrypted_data, iv: iv_str })
                        });
                        if (!res.ok) { const err = await res.json(); throw new Error(err.error); }
                        document.getElementById('site').value = '';
                        document.getElementById('editUsername').value = '';
                        document.getElementById('password').value = '';
                        document.getElementById('note').value = '';
document.getElementById('note').style.height = '44px';
                        updateStrengthIndicator();
                    }
                    await loadSecrets();
                } catch (e) {
                    alert(t('form.error.saveFailed', {msg: e.message}));
                }
            }

            async function loadSecrets() {
                if (!cachedMasterKey || !cachedAuthKey) return;
                const res = await fetch('/api/secrets', { headers: { 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey, 'x-lang': currentLang }});
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
                            updated_at: item.updated_at || null,
                            pinned: item.pinned || 0
                        });
                    } catch (e) {}
                }
                renderSecrets(getFilteredAndSorted());
            }

            /* ====== 排序 & 搜索 ====== */
            function getFilteredAndSorted() {
                const query = document.getElementById('searchBar').value.toLowerCase();
                const siteFilter = document.getElementById('siteFilter').value;

                var filtered = allDecryptedSecrets.filter(function(item) {
                    if (siteFilter && item.site !== siteFilter) return false;
                    return item.site.toLowerCase().includes(query) ||
                           item.username.toLowerCase().includes(query) ||
                           item.note.toLowerCase().includes(query);
                });

                /* 组内统一按置顶优先 + id DESC */
                filtered.sort(function(a, b) {
                    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
                    return b.id - a.id;
                });

                updateSiteFilter();
                return filtered;
            }

            function updateSiteFilter() {
                var sel = document.getElementById('siteFilter');
                var panel = document.getElementById('siteDropdownPanel');
                var cur = sel.value;
                var sites = {};
                for (var i = 0; i < allDecryptedSecrets.length; i++) {
                    sites[allDecryptedSecrets[i].site] = true;
                }
                var siteList = Object.keys(sites).sort(function(a, b) { return a.localeCompare(b); });
                sel.innerHTML = '<option value="">' + t('list.filter.all') + '</option>';
                panel.innerHTML = '<div class="sf-opt"' + (cur === '' ? ' style="font-weight:600;background:var(--secondary-bg);"' : '') + ' onclick="selectSite(&#39;&#39;)">' + t('list.filter.all') + '</div>';
                for (var i = 0; i < siteList.length; i++) {
                    sel.innerHTML += '<option value="' + siteList[i] + '"' + (siteList[i] === cur ? ' selected' : '') + '>' + siteList[i] + '</option>';
                    panel.innerHTML += '<div class="sf-opt"' + (siteList[i] === cur ? ' style="font-weight:600;background:var(--secondary-bg);"' : '') + ' onclick="selectSite(&#39;' + siteList[i] + '&#39;)">' + escapeHtml(siteList[i]) + '</div>';
                }
            }

            function toggleSiteDropdown(e) {
                if (e) e.stopPropagation();
                var panel = document.getElementById('siteDropdownPanel');
                panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
            }

            function selectSite(val) {
                document.getElementById('siteFilter').value = val;
                document.getElementById('siteFilterLabel').textContent = val || t('list.filter.all');
                document.getElementById('siteDropdownPanel').style.display = 'none';
                document.getElementById('siteFilter').dispatchEvent(new Event('change'));
            }

            /* ====== 排序下拉 ====== */
            function toggleSortDropdown(e) {
                if (e) e.stopPropagation();
                var panel = document.getElementById('sortDropdownPanel');
                panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
            }

            function selectSort(val, _label) {
                document.getElementById('sortSelect').value = val;
                var sortLabels = { newest: 'list.sort.newest', oldest: 'list.sort.oldest', updated: 'list.sort.updated', most: 'list.sort.most' };
                document.getElementById('sortLabel').textContent = t(sortLabels[val] || val);
                document.getElementById('sortDropdownPanel').style.display = 'none';
                filterSecrets();
            }

            /* 填充排序下拉选项 */
            function initSortDropdown() {
                var sel = document.getElementById('sortSelect');
                var panel = document.getElementById('sortDropdownPanel');
                var labels = { newest: 'list.sort.newest', oldest: 'list.sort.oldest', updated: 'list.sort.updated', most: 'list.sort.most' };
                panel.innerHTML = '';
                for (var i = 0; i < sel.options.length; i++) {
                    var val = sel.options[i].value;
                    var label = t(labels[val] || val);
                    sel.options[i].textContent = t(labels[val] || val);
                    panel.innerHTML += '<div class="sf-opt" onclick="selectSort(&#39;' + val + '&#39;,&#39;' + label + '&#39;)">' + label + '</div>';
                }
            }
            initSortDropdown();

            /* 点击其他地方关闭下拉 */
            document.addEventListener('click', function(e) {
                var el1 = e.target.closest ? e.target.closest('#siteFilterDisplay') : null;
                var el2 = e.target.closest ? e.target.closest('#sortDisplay') : null;
                if (!el1) {
                    var p = document.getElementById('siteDropdownPanel');
                    if (p) p.style.display = 'none';
                }
                if (!el2) {
                    var p = document.getElementById('sortDropdownPanel');
                    if (p) p.style.display = 'none';
                }
            });

            /* 自定义下拉选项样式 */
            (function() {
                var style = document.createElement('style');
                style.textContent = '.sf-opt{padding:8px 14px;cursor:pointer;font-size:14px;border-radius:6px;margin:2px 4px}.sf-opt:hover{background:var(--secondary-bg)}';
                document.head.appendChild(style);
            })();

            function filterSecrets() {
                renderSecrets(getFilteredAndSorted());
            }

            function renderSecrets(secrets) {
                var listDiv = document.getElementById('list');
                if (secrets.length === 0) {
                    listDiv.innerHTML = '<p style="color:var(--text-secondary); text-align:center;">' + t('list.empty') + '</p>';
                    return;
                }

                /* 先拼完整 HTML，再一次赋值，避免 innerHTML += 导致浏览器自动闭合未完成的 div */
                var html = '';

                /* 按 site 分组 */
                var groups = {};
                for (var gi = 0; gi < secrets.length; gi++) {
                    var gitem = secrets[gi];
                    if (!groups[gitem.site]) groups[gitem.site] = [];
                    groups[gitem.site].push(gitem);
                }

                /* 组排序 */
                var sortBy = document.getElementById('sortSelect').value;
                var siteNames = Object.keys(groups).sort(function(a, b) {
                    var ga = groups[a], gb = groups[b];
                    switch (sortBy) {
                        case 'oldest':
                            return Math.min.apply(null, ga.map(function(x) { return x.id; })) - Math.min.apply(null, gb.map(function(x) { return x.id; }));
                        case 'updated':
                            return Math.max.apply(null, gb.map(function(x) { return new Date(x.updated_at || 0); })) - Math.max.apply(null, ga.map(function(x) { return new Date(x.updated_at || 0); }));
                        case 'most':
                            return gb.length - ga.length;
                        default: /* newest */
                            return Math.max.apply(null, gb.map(function(x) { return x.id; })) - Math.max.apply(null, ga.map(function(x) { return x.id; }));
                    }
                });

                for (var g = 0; g < siteNames.length; g++) {
                    var site = siteNames[g];
                    var items = groups[site];
                    var siteFilter = document.getElementById('siteFilter').value;
                    var expanded = siteFilter !== '' || items.length <= 2;
                    var groupId = 'group-' + g;

                    /* 组头 */
                    html += '<div class="group-header" data-group="' + groupId + '" id="' + groupId + '-head">' +
                        '<span>' + escapeHtml(site) + ' <button class="secondary" onclick="event.stopPropagation();navigator.clipboard.writeText(&#39;' + escapeHtml(site) + '&#39;);showToast(&#39;' + t('list.copy.site') + '&#39;)" style="padding:2px 8px;font-size:11px;margin:0 0 0 8px;width:auto;display:inline;background:rgba(0,0,0,0.06);border:1px solid rgba(0,0,0,0.12);">' + t('list.copy') + '</button>' +
                        ' <button class="secondary" onclick="event.stopPropagation();window.open(\\'https://' + escapeHtml(site) + '\\',\\'_blank\\')" style="padding:2px 8px;font-size:11px;margin:0 0 0 4px;width:auto;display:inline;background:rgba(0,0,0,0.06);border:1px solid rgba(0,0,0,0.12);">' + t('list.open') + '</button> <span class="count">' + t('list.accounts', {n: items.length}) + '</span></span>' +
                        '<span id="' + groupId + '-arrow">' + (expanded ? '▾' : '▸') + '</span>' +
                    '</div>';

                    /* 组内容 */
                    html += '<div class="group-body" id="' + groupId + '" style="' + (expanded ? '' : 'display: none;') + '">';

                    for (var k = 0; k < items.length; k++) {
                        var item = items[k];
                        var noteHtml = item.note ? '<div style="margin:6px 0 0;font-size:13px;color:var(--text-secondary);background:var(--item-bg);padding:6px 10px;border-radius:6px;border:1px solid var(--border);word-break:break-word;white-space:pre-wrap;line-height:1.4;">📝 ' + escapeHtml(item.note).split('\\n').join('<br>') + '</div>' : '';
                        var timeHtml = '<div class="time-ago">🕐 ' + timeAgo(item.updated_at) + '</div>';

                        html += '<div class="secret-item" style="position:relative;">' +
                            '<button class="pin-btn-top" onclick="togglePin(' + item.id + ')" title="' + (item.pinned ? t('list.pin.on') : t('list.pin.off')) + '">' + (item.pinned ? '📌' : '📍') + '</button>' +
                            '<div style="flex-grow: 1;">' +
                                '<div style="margin: 6px 0 0; font-size: 14px; color:var(--text-secondary);">' +
                                    t('list.label.account') + '<span id="user-' + item.id + '">' + escapeHtml(item.username) + '</span>' +
                                    '<button class="secondary copy-btn" onclick="copyToClipboard(&#39;user-' + item.id + '&#39;, &#39;' + t('list.copied.account') + '&#39;)">' + t('list.copy') + '</button>' +
                                '</div>' +
                                '<div style="margin: 4px 0 0; font-size: 14px; color:var(--text-secondary);">' +
                                    t('list.label.password') + '<span id="pwd-' + item.id + '" data-pwd="' + escapeHtml(item.password) + '">•••••••</span>' +
                                    '<button class="secondary copy-btn" onclick="togglePasswordVisibility(&#39;pwd-' + item.id + '&#39;, this)">' + t('list.btn.show') + '</button>' +
                                    '<button class="secondary copy-btn" onclick="copyToClipboard(&#39;pwd-' + item.id + '&#39;, &#39;' + t('list.copied.password') + '&#39;)">' + t('list.copy') + '</button>' +
                                '</div>' +
                                noteHtml + timeHtml +
                            '</div>' +
                            '<div class="item-actions">' +
                                '<button class="secondary small-btn" onclick="editSecret(' + item.id + ')" style="width: auto;">' + t('list.btn.edit') + '</button>' +
                                '<button class="danger small-btn" onclick="deleteSecret(' + item.id + ')" style="width: auto;">' + t('list.btn.delete') + '</button>' +
                            '</div>' +
                        '</div>';
                    }

                    html += '</div>'; /* group-body */
                }

                listDiv.innerHTML = html;
            }

            document.getElementById('list').addEventListener('click', function(e) {
                var el = e.target.closest('.group-header');
                if (!el) return;
                var groupId = el.getAttribute('data-group');
                var body = document.getElementById(groupId);
                var arrow = document.getElementById(groupId + '-arrow');
                if (!body) return;
                if (body.style.display === 'none') {
                    body.style.display = '';
                    arrow.textContent = '▾';
                } else {
                    body.style.display = 'none';
                    arrow.textContent = '▸';
                }
            });

            /* ====== 编辑功能 ====== */
            function editSecret(id) {
                var item = allDecryptedSecrets.find(function(s) { return s.id === id; });
                if (!item) return;

                editTargetId = id;
                editOriginalPassword = item.password;
                document.getElementById('saveFormTitle').textContent = t('form.title.edit');
                document.getElementById('saveBtn').textContent = t('form.update');
                document.getElementById('saveBtn').style.background = '#30d158';
                document.getElementById('cancelEditBtn').style.display = 'inline-block';
                document.getElementById('site').value = item.site;
                document.getElementById('editUsername').value = item.username;
                document.getElementById('password').value = item.password;
                document.getElementById('note').value = item.note;
                autoResize(document.getElementById('note'));
                updateStrengthIndicator();
                /* 滚动到表单 */
                document.querySelector('.card:nth-of-type(3)').scrollIntoView({ behavior: 'smooth' });
            }

            async function deleteSecret(id) {
                if (!cachedAuthKey) return;
                if (confirm(t('confirm.delete'))) {
                    const res = await fetch('/api/secrets/' + id, { method: 'DELETE', headers: { 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey, 'x-lang': currentLang }});
                    if (res.ok) {
                        if (editTargetId === id) cancelEdit();
                        await loadSecrets();
                    }
                }
            }

            function togglePin(id) {
                if (!cachedAuthKey) return;
                /* 先本地翻转 */
                for (var i = 0; i < allDecryptedSecrets.length; i++) {
                    if (allDecryptedSecrets[i].id === id) {
                        allDecryptedSecrets[i].pinned = allDecryptedSecrets[i].pinned ? 0 : 1;
                        break;
                    }
                }
                /* 保存展开状态 */
                var expandedState = {};
                var oldBodies = document.querySelectorAll('.group-body');
                for (var i = 0; i < oldBodies.length; i++) {
                    expandedState[oldBodies[i].id] = oldBodies[i].style.display !== 'none';
                }
                renderSecrets(getFilteredAndSorted());
                /* 恢复展开状态 */
                for (var key in expandedState) {
                    var body = document.getElementById(key);
                    var arrow = document.getElementById(key + '-arrow');
                    if (body) {
                        if (expandedState[key]) {
                            body.style.display = '';
                            if (arrow) arrow.textContent = '▾';
                        } else {
                            body.style.display = 'none';
                            if (arrow) arrow.textContent = '▸';
                        }
                    }
                }
                fetch('/api/secrets/' + id + '/pin', { method: 'POST', headers: { 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey, 'x-lang': currentLang }});
            }

            /* ====== 密码生成器 ====== */
            function toggleGenSettings() {
                const panel = document.getElementById('genSettingsPanel');
                panel.style.display = panel.style.display === "none" ? "block" : "none";
            }

            function togglePwdVisibility() {
                var input = document.getElementById('password');
                var btn = document.getElementById('togglePwdBtn');
                if (input.type === 'password') {
                    input.type = 'text'; btn.textContent = '🙈';
                } else {
                    input.type = 'password'; btn.textContent = '👁';
                }
            }

            function generatePassword() {
                const length = parseInt(document.getElementById('genLength').value) || 16;
                let chars = '';
                if (document.getElementById('genUpper').checked) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
                if (document.getElementById('genLower').checked) chars += 'abcdefghijklmnopqrstuvwxyz';
                if (document.getElementById('genNumber').checked) chars += '0123456789';
                if (document.getElementById('genSymbols').checked) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
                if (!chars) return alert(t('form.error.genCharset'));

                /* 分离特殊符号和非特殊符号 */
                var symbolRegex = /[^A-Za-z0-9]/g;
                var symbols = chars.match(symbolRegex) || [];
                var nonSymbols = chars.replace(symbolRegex, '');

                var buf = new Uint32Array(length + 1);
                window.crypto.getRandomValues(buf);
                var password = '';

                if (symbols.length > 0 && nonSymbols.length > 0) {
                    /* 随机决定用 0~3 个符号 */
                    var symCount = buf[0] % Math.min(4, length);
                    var result = [];
                    for (var i = 0; i < symCount; i++) result.push(symbols[buf[i + 1] % symbols.length]);
                    for (var i = symCount; i < length; i++) result.push(nonSymbols[buf[i + 1] % nonSymbols.length]);
                    /* Fisher-Yates 洗牌 */
                    for (var i = result.length - 1; i > 0; i--) {
                        var j = buf[i + 1] % (i + 1);
                        var tmp = result[i]; result[i] = result[j]; result[j] = tmp;
                    }
                    password = result.join('');
                } else {
                    /* 只有符号或只有非符号，直接生成 */
                    for (var i = 0; i < length; i++) password += chars[buf[i] % chars.length];
                }

                document.getElementById('password').value = password;
                updateStrengthIndicator();
            }

            function togglePasswordVisibility(id, btn) {
                var el = document.getElementById(id);
                if (el.textContent === '•••••••') {
                    el.textContent = el.getAttribute('data-pwd');
                    btn.innerText = t('list.btn.hide');
                } else {
                    el.textContent = '•••••••';
                    btn.innerText = t('list.btn.show');
                }
            }

            function copyToClipboard(elementId, msg) {
                var el = document.getElementById(elementId);
                var text = el.getAttribute('data-pwd') || el.textContent;
                navigator.clipboard.writeText(text);
                showToast(msg || t('list.copied'));
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

            function autoResize(el) {
                el.style.height = '44px';
                el.style.height = Math.min(el.scrollHeight, 120) + 'px';
            }

            function escapeHtml(string) {
                return String(string).replace(/[&<>"']/g, function (s) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[s]; });
            }

            /* ====== 导出 / 导入 ====== */
            function exportJSON() {
                if (allDecryptedSecrets.length === 0) return alert(t('export.empty'));
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
                if (!confirm(t('import.confirm'))) {
                    event.target.value = ''; return;
                }

                const reader = new FileReader();
                reader.onload = async function(e) {
                    try {
                        const importedData = JSON.parse(e.target.result);
                        if (!Array.isArray(importedData)) throw new Error(t('import.error.format'));

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
                                headers: { 'Content-Type': 'application/json', 'x-username': cachedUsername, 'x-auth-key': cachedAuthKey, 'x-lang': currentLang },
                                body: JSON.stringify({ encrypted_data, iv: iv_str })
                            });
                            if (res.ok) successCount++;
                        }
                        alert(t('import.success', {n: successCount}));
                        await loadSecrets();
                    } catch (err) {
                        alert(t('import.error.failed', {msg: err.message}));
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
