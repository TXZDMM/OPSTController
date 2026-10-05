# OPSTcontroller / 扩展名保护卫士

**阻止第三方软件私自篡改文件扩展名默认打开方式**
**Prevent third-party software from hijacking file extension default associations**

> **开发说明**：本项目由 AI 辅助完成。源码逻辑与实现由作者完成，AI 提供知识与代码片段，并参与代码整理、修错与注释（本说明为如实披露，非免责）。

---

## 功能特性 / Features

- **一键保护所有扩展名**：扫描并保护系统中全部文件扩展名的默认打开方式
- **8 个注册表保护位置**（7 项主保护 + 1 项补充校验）：
  - `HKCR\.ext` / `HKCU\Software\Classes\.ext` / `HKLM\SOFTWARE\Classes\.ext`
  - `UserChoice ProgId` / `UserChoice Hash`
  - `HKCR\{ProgId}\shell\open\command` / `HKCU\Software\Classes\{ProgId}\shell\open\command`
  - 补充校验：`HKLM\SOFTWARE\Classes\{ProgId}\shell\open\command`
- **实时监控 + 自动恢复**：检测到篡改立即恢复到基准值，恢复后回读验证
- **分层防御（BH0–BH5）**：仅检测 → 自动恢复 → ACL 锁定 → System 完整性标签 → Untrusted 降权 → 进程冻结
- **持续篡改防御**：单扩展名 20 秒内被更改 2 次即进入持续模式并锁定注册表键
- **批量篡改防御**：同一 ProgId 60 秒内涉及 ≥8 个扩展名 → 锁定相关全部扩展名并触发进程打击
- **右下角通知**：非模态滑入通知，含"单次同意"和"打开主程序"按钮，超时默认阻止
- **基准管理**：支持"以目前方式为基准"/"以默认方式为基准"（可导入 .json），默认保留 5 个历史版本
- **TI/SYSTEM 权限**：内置 NSudo 提权，可选 user / administrator / system / TI 四档
- **开机自启 + 后台常驻 + 看门狗自恢复**
- **完整日志与审计**：所有操作写入 `userdata/protector.log`，可导出审计记录（进程名/路径/命令行/数字签名/注册表变更）

- One-click protection for all file extensions
- 8 registry locations monitored per extension (7 primary + 1 supplementary)
- Real-time monitoring + auto-recovery with verification
- Layered defense: BH0 detect → BH1 restore → BH2 ACL lock → BH3 System label → BH4 Untrusted → BH5 freeze
- Persistent tamper defense: 2 changes within 20s triggers lock
- Batch tamper defense: same ProgId touching 8+ extensions within 60s
- Toast notifications with "Allow once" and "Open main window" buttons
- Baseline management with 5 history versions and import support
- TI/SYSTEM privilege via bundled NSudo
- Auto-start, background resident and watchdog self-recovery
- Complete logging and auditable export

---

## ⚠️ 重要行为说明（使用前必读） / Important Behavior Disclosure

本程序是安全防护工具，但包含以下**强行为**，请在使用前知悉：

1. **进程打击 / Process enforcement**：检测到持续或批量篡改时，会对关联的嫌疑进程执行降权、挂起、**强终止**（TerminateProcess → taskkill → wmic → Stop-Process 多方式重试），并将重复关联的进程自动拉入黑名单；同一进程累计拉黑 10 次进入红名单。系统关键进程（system、lsass、svchost、explorer 等）始终被跳过。
2. **进程自保护 / Self-protection**：以 TI/SYSTEM 权限运行时，程序会设置自身进程 ACL，普通用户（含管理员）无法通过任务管理器直接终止本进程。完全退出请运行随附的 `停止OPSTcontroller.bat` 或 `OPSTcontroller.exe --stop`（自我保护实例无法被普通令牌终止时，`--stop` 会自动请求管理员权限执行强杀，UAC 关闭时静默完成）。
3. **注册表锁键 / Registry locking**：持续/批量篡改时会锁定 UserChoice 等注册表键的 ACL（拒绝 Users/Administrators 写入），程序退出时自动解锁。
4. **高权限运行 / High privilege**：默认以 TrustedInstaller 权限运行，可在设置中改为 administrator / system / user。未签名提权型工具可能被杀毒软件误报，请自行评估后再安装。
5. **误报风险 / False-positive risk**：极少数情况下可能将"关联缺失/命令缺失"误判为篡改。请勿与其它修改文件关联的软件同时运行，并定期备份 `userdata/` 目录。

---

## 判定参数（与实现一致） / Detection Parameters

| 项目 / Item | 数值 / Value |
|---|---|
| 单扩展名持续篡改阈值 | 20 秒内 2 次（SINGLE_WINDOW=20 / SINGLE_THRESHOLD=2） |
| 批量篡改阈值 | 60 秒内同一 ProgId 涉及 ≥8 个扩展名（BATCH_WINDOW=60 / BATCH_THRESHOLD=8） |
| 锁定时长 | 第 1–2 次 60 秒，第 3 次起 300 秒 |
| 持续模式冷却 | 全部解锁后 30 秒无新篡改即解除 |
| 通知默认时长 | 8 秒，超时默认阻止 |
| 基准历史版本数 | 默认 5（可调 1–20） |

---

## 目录结构 / Directory Structure

```
OPSTcontroller.exe          # 主程序（含版本信息）
runtime/                    # 运行时依赖
  ├── NSudoLC.exe           # 提权工具
  ├── NSudoLG.exe / NSudoAPI.dll / NSudoDM.dll / MoPlugin.dll
  └── NSudo-LICENSE.md      # NSudo 的 MIT 许可文本
userdata/                   # 用户数据（首次运行自动生成）
  ├── baseline.json         # 基准文件
  ├── config.json           # 配置
  ├── protector.log         # 日志
  ├── program_names.json    # 程序名映射表
  └── baseline_history/     # 历史版本
停止OPSTcontroller.bat      # 停止程序
README.md / LICENSE         # 说明与许可
```

---

## 使用方法 / Usage

### 首次运行 / First Run

1. 双击 `OPSTcontroller.exe`，同意 UAC 提权
2. 选择基准方式：
   - **以目前方式为基准**：保存当前所有扩展名的默认打开方式
   - **以默认方式为基准**：清除 UserChoice，回退到系统默认关联（可导入 .json 基准文件）
3. 等待基准创建完成（约 5-10 秒）
4. 程序自动开启实时保护

1. Double-click `OPSTcontroller.exe`, accept UAC
2. Choose baseline mode: **Current mode** or **Default mode** (or import a .json baseline)
3. Wait for baseline creation
4. Protection starts automatically

### 日常使用 / Daily Use

- 关闭主窗口 = 后台常驻，继续保护；再次双击 exe = 唤出主窗口
- 检测到篡改时右下角弹出通知，超时后默认阻止
- 点击"单次同意" = 允许本次更改并更新基准
- 运行 `停止OPSTcontroller.bat` = 完全退出程序

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
| 默认阻止时间 / Block timeout | 弹窗超时秒数（1–180）/ Toast timeout seconds |
| 批量弹窗模式 / Batch popup | 单个(队列) / 同时(堆叠) |
| 运行模式 / Operation mode | 正常 / 临时免打扰 / 游戏 / 演示 / 静默 / 暂停 |
| 持续模式是否终止进程 | 可关闭（仅锁定注册表） |
| 每次启动清空日志 / Clear log on start | 是/否 / Yes/No |
| 记录级别 / Audit level | 极简 / 普通 / 详细 / 完整 |
| 基准保留版本数 / History versions | 默认 5 / Default 5 |

---

## 持续篡改防御 / Persistent Tamper Defense

单扩展名在 20 秒内被更改 2 次，或同一 ProgId 在 60 秒内涉及 8 个以上扩展名时，程序自动：

1. 进入持续/批量保护模式，不再弹窗
2. 锁定 UserChoice 及关联注册表键（拒绝 Users/Administrators 写入）
3. 静默恢复被篡改的值，并验证恢复结果
4. 对关联嫌疑进程执行降权/挂起/冻结（可关闭）
5. 锁定到期（60 秒/300 秒）自动解锁，进入 30 秒观察期后恢复正常模式

When a single extension is changed 2 times within 20s, or 8+ extensions are touched by the same ProgId within 60s:

1. Enter persistent/batch protection mode (no more popups)
2. Lock the UserChoice and related registry keys (deny write for Users/Administrators)
3. Silently restore and verify tampered values
4. Lower/suspend/freeze the associated suspect processes (configurable)
5. Auto-unlock after the lock period, then resume normal mode after a 30s observation window

---

## 构建方法 / Building

- 依赖：Python 3.13 + 虚拟环境（`requirements.txt`: `pyinstaller>=6.0`）
- **一键构建**：运行 `build.bat`（自动构建 exe 并组装发布目录：runtime 二进制、NSudo 许可、README/LICENSE、停止脚本、空白 userdata 模板）
- NSudo 二进制位于仓库 `Win32/` 目录，构建时自动复制到 `runtime/`
- 源码运行时可通过环境变量 `OPST_NSudo_PATH` 指定 NSudo 所在目录

---

## 项目地址 / Repository

https://github.com/TXZDMM/OPSTController

---

## 注意事项 / Notes

- 程序需要管理员或 TI 权限才能有效保护注册表
- 首次运行建议关闭其他正在修改文件关联的软件（如 PotPlayer、迅雷看看等）
- 基准文件存储在 `userdata/` 目录，重装程序时请备份
- 本程序仅保护文件扩展名关联相关注册表项；进程打击与自保护行为详见上文"重要行为说明"
- 未签名程序可能被杀毒软件误报，发布新版本建议完成代码签名

- Requires admin or TI privileges
- Close association-modifying software during first run
- Backup `userdata/` before reinstalling
- See "Important Behavior Disclosure" above for process enforcement and self-protection
- Unsigned builds may trigger AV false positives; consider code signing for releases

---

## 许可证 / License

- 本程序：MIT License（见 `LICENSE`）
- 内置 NSudo：MIT License（M2-Team，见 `runtime/NSudo-LICENSE.md`）
- 打包运行时（Python、PyInstaller、Tk 等）：按各自许可证分发

版本历史见 `CHANGELOG.md`。
