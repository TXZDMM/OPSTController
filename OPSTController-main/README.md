

# OPSTcontroller / 扩展名保护卫士

**阻止第三方软件私自篡改文件扩展名默认打开方式**
**Prevent third-party software from hijacking file extension default associations**

---

## 功能特性 / Features

- **一键保护所有扩展名**：扫描并保护系统中全部文件扩展名的默认打开方式
- **7项注册表防护**：每个扩展名监控7个关键注册表位置
  - `HKCR\.ext` / `HKCU\Software\Classes\.ext` / `HKLM\SOFTWARE\Classes\.ext`
  - `UserChoice ProgId` / `UserChoice Hash`
  - `HKCR\{ProgId}\shell\open\command` / `HKCU\Software\Classes\{ProgId}\shell\open\command`
- **实时监控 + 自动恢复**：检测到篡改立即恢复到基准值
- **分层防御**：快速检测 → 重复识别 → 静默保护 → 注册表锁死
- **持续篡改防御**：同一扩展名被连续篡改3次后自动锁定注册表键，拒绝第三方写入
- **右下角通知**：非模态滑入通知，含"单次同意"和"打开主程序"按钮
- **基准管理**：支持"以目前方式为基准"/"以默认方式为基准"，保留5个历史版本
- **TI/SYSTEM 权限**：内置 NSudo 提权，以 TrustedInstaller 权限运行，无视权限限制
- **开机自启 + 后台常驻**：关闭窗口后后台继续保护
- **完整日志**：所有操作记录到 `userdata/protector.log`

- **One-click protection** for all file extensions
- **7 registry locations** monitored per extension
- **Real-time monitoring + auto-recovery**
- **Layered defense**: detect → identify repetition → silent protection → registry lock
- **Persistent tamper defense**: auto-locks registry keys after 3 repeated changes
- **Toast notifications** with "Allow once" and "Open main window" buttons
- **Baseline management** with 5 history versions
- **TI/SYSTEM privilege** via built-in NSudo
- **Auto-start + background resident**
- **Complete logging**

---

## 日志 / Log

(大版本，小版本，bug) / ((major version, minor version, bug)
v0.1.0(第一版) / (First edition)
v0.2.0(更新了频繁篡改的防护措施和输出，减少了频繁防护的桌面图标闪烁) / (Updated the protection measures and outputs that were frequently tampered with, reducing the flickering of desktop icons from frequent protection.)

## 目录结构 / Directory Structure

```
OPSTcontroller.exe          # 主程序 / Main program
runtime/                    # 运行时依赖 / Runtime dependencies
  ├── NSudoLC.exe           # 提权工具 / Privilege escalation
  ├── NSudoAPI.dll
  ├── NSudo.json
  └── ... (Python runtime)
userdata/                   # 用户数据 / User data
  ├── baseline.json         # 基准文件 / Baseline
  ├── config.json           # 配置 / Config
  ├── protector.log         # 日志 / Log
  └── baseline_history/     # 历史版本 / History versions
停止OPSTcontroller.bat      # 停止程序 / Stop script
README.md                   # 本文件 / This file
```

---

## 使用方法 / Usage

### 首次运行 / First Run

1. 双击 `OPSTcontroller.exe`，同意 UAC 提权
2. 选择基准方式：
   - **以目前方式为基准**：保存当前所有扩展名的默认打开方式
   - **以默认方式为基准**：清除 UserChoice，回退到系统默认关联
3. 等待基准创建完成（约5-10秒）
4. 程序自动开启实时保护

1. Double-click `OPSTcontroller.exe`, accept UAC
2. Choose baseline mode:
   - **Current mode**: save current associations
   - **Default mode**: clear UserChoice, fall back to system defaults
3. Wait for baseline creation
4. Protection starts automatically

### 日常使用 / Daily Use

- 关闭主窗口 = 后台常驻，继续保护
- 再次双击 exe = 唤出主窗口
- 检测到篡改时右下角弹出通知，8秒后默认阻止
- 点击"单次同意" = 允许本次更改并更新基准
- 运行 `停止OPSTcontroller.bat` = 完全退出程序

- Close window = background resident
- Double-click again = restore window
- Toast notification on tamper, auto-block after 8s
- "Allow once" = accept change and update baseline
- Run `停止OPSTcontroller.bat` = fully exit

### 停止程序 / Stop

```cmd
停止OPSTcontroller.bat
```
或 / or:
```cmd
OPSTcontroller.exe --stop
```

---

## 设置项 / Settings

| 设置 / Setting | 说明 / Description |
|---|---|
| 默认权限 / Default Permission | user / administrator / system / t (TI) |
| 开机自启 / Auto-start | 默认开启 / Enabled by default |
| 是否弹窗 / Show popup | 关闭后静默阻止 / Silent block when off |
| 默认阻止时间 / Block timeout | 弹窗超时秒数 / Toast timeout seconds |
| 每次启动清空日志 / Clear log on start | 是/否 / Yes/No |
| 基准保留版本数 / History versions | 默认5 / Default 5 |

---

## 持续篡改防御 / Persistent Tamper Defense

当同一扩展名在60秒内被相同方式篡改3次时，程序自动：
1. 进入持续保护模式，不再弹窗
2. 锁定 UserChoice 注册表键（拒绝 Users/Administrators 写入）
3. 静默恢复被篡改的值
4. 20秒无新更改后自动解锁，恢复正常模式

When the same extension is tampered identically 3 times within 60 seconds:
1. Enter persistent protection mode (no more popups)
2. Lock the UserChoice registry key (deny write for Users/Administrators)
3. Silently restore tampered values
4. Auto-unlock after 20 seconds of no new changes

---

## 项目地址 / Repository

https://github.com/TXZDMM/OPSTController

---

## 注意事项 / Notes

- 程序需要管理员或 TI 权限才能有效保护注册表
- 首次运行建议关闭其他正在修改文件关联的软件（如 PotPlayer、迅雷看看等）
- 基准文件存储在 `userdata/` 目录，重装程序时请备份
- 本程序仅保护文件扩展名关联，不修改其他系统设置

- Requires admin or TI privileges
- Close association-modifying software during first run
- Backup `userdata/` before reinstalling
- Only protects file extension associations

---

## 许可证 / License

MIT License
