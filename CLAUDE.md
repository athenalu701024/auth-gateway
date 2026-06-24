# Auth Gateway

IGS 廣告監控平台的**統一登入閘道**。使用者先在這裡登入，拿到 JWT 之後才能訪問 apple-ads / google-ads / meta-ads 三個廣告管理服務。Role-based 帳號管理（admin / viewer），支援 Email domain 白名單。

## 技術棧
- Node.js (ESM, `"type": "module"`) + Express 5
- PostgreSQL via `pg`
- `bcryptjs`（密碼雜湊）+ `jsonwebtoken`（session token）+ `cookie-parser`

## 本地啟動
```bash
npm install
cp .env.example .env       # 填 DATABASE_URL / JWT_SECRET / ADMIN_EMAIL / ADMIN_PASSWORD
npm run dev                # 預設 PORT=4000；`node --watch` 自動重啟
# DB schema 由 server.js 啟動時 initDB() 自動建立，無需另外手動初始化
```

## 部署
- **GitHub**: `athenalu701024/auth-gateway`
- **Railway service**: `auth-gateway`（綁定 `master` 自動部署）
- **URL**: https://auth-gateway-production-c321.up.railway.app/
- **→ 此為整個 IGS 廣告監控平台的主入口**

## 架構

### Single-file 設計
所有邏輯集中在 [server.js](server.js)（~360 行）。路由分 3 組：

| 路由 | 說明 |
|---|---|
| `POST /api/auth/login` | 登入，回傳 JWT（設 cookie + body 同時） |
| `POST /api/auth/logout` | 清除 cookie |
| `GET  /api/auth/verify` | 驗證 token（requireAuth） |
| `GET  /api/auth/me` | 取當前使用者資料（requireAuth） |
| `POST /api/auth/change-password` | 改密碼（requireAuth） |
| `GET/POST/PUT/DELETE /api/admin/users` | 使用者 CRUD（requireAdmin） |
| `GET  /api/health` | 健康檢查（公開） |

### Token 雙通道取得
`getTokenFromRequest()` 同時支援：
1. `auth_token` cookie（瀏覽器流程）
2. `Authorization: Bearer <token>` header（API 呼叫流程）

## 關鍵概念

### Email domain 白名單
`ALLOWED_EMAIL_DOMAIN`（預設 `igs.com.tw`）限制只有特定網域可註冊/登入。

### 初始 admin seed
資料庫首次啟動時用 `ADMIN_EMAIL` + `ADMIN_PASSWORD` 建立初始 admin。
**之後改這些 env 變數不會影響既有帳號** — 密碼已用 `bcrypt.hash(pwd, 12)` 存入 DB，要改得走 `/api/auth/change-password`。

### CORS 白名單（已強制）
不在白名單的瀏覽器 origin 會被擋（callback error）；無 Origin header 的請求（server-to-server / curl / 同源）仍放行。
- 平台已知 origin（auth-gateway 本身 + meta/apple/google/applovin 四個 production URL）已**內建**在 server.js 的 `DEFAULT_ALLOWED_ORIGINS`，即使沒設 env 也不會被擋。
- `ALLOWED_ORIGINS`（逗號分隔）的值會與內建清單**合併**（非取代）。新增其他下游服務時，把它的 URL 加進這個 env 或 `DEFAULT_ALLOWED_ORIGINS` 即可。

### 工具可見性（per-user，僅隱藏磚塊）
`users.allowed_apps`（`TEXT[]`）控制每個帳號在入口看得到哪些工具：
- `NULL` = 看得到全部（現有帳號預設，向後相容）
- 陣列（存 `APP_CONFIGS` 的 `urlKey`）= 只看清單內；空陣列 = 都看不到
- admin 在「使用者管理」的新增/編輯 modal 用 checkbox 勾選；前端 `renderApps()` 依此過濾。
- 入口載入時打 `/api/auth/me`（查 DB）拿最新 `allowed_apps`，所以改完使用者**下次刷新即生效、不必重新登入**。
- ⚠️ **這只隱藏入口磚塊，不是真正的存取控制**。知道下游網址且 token 有效的人仍可直接進入（gateway `/api/auth/verify` 只驗登入、不驗工具權限）。要真正擋下需讓下游服務檢查 per-app 權限。

## Security-sensitive 改動必知

- 🔴 **`JWT_SECRET` 必須是強隨機值**。程式 fallback 的 `'dev-secret-change-in-production'` 只給 dev 用；production 必須覆寫且 ≥ 256 bits entropy。
  - 產生方式：`node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`
  - 輪換後所有現有 session 會失效，使用者需重新登入（預期行為）
- 🔴 **不要** 把 secret / token / password 印到 log 或塞進 API response
- 🔴 新增需要登入的端點 → 掛 `requireAuth` middleware；需要 admin 權限再掛 `requireAdmin`
- 🔴 production 環境下 cookie 是 `secure: true` + `sameSite: 'none'` — 跨站使用時 downstream service 需 HTTPS

## 資安事件處理紀錄
詳見 memory（`feedback_secret_handling.md`）— 2026-04-21 曾發生 JWT_SECRET 洩漏，已輪換並建立 clip-based workflow 避免重現。
