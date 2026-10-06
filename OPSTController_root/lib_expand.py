# -*- coding: utf-8 -*-
"""扩充 program_names.json：现有库 + EXTRA_A/B/C/D + 常见子进程变体 → 去重 → 同步三副本。"""
import json, os, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root"
COPIES = [
    os.path.join(ROOT, "userdata", "program_names.json"),
    r"C:\Users\TXZDM\Desktop\OPSTcontroller_Release\userdata\program_names.json",
    r"C:\Users\TXZDM\Desktop\OPSTcontroller_Releasedontaction\userdata\program_names.json",
]

# 载入现有库
entries = []
try:
    with open(COPIES[0], "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        entries = [[str(a).strip(), str(b).strip()] for a, b in data if a and b]
    elif isinstance(data, dict):
        entries = [[str(k).strip(), str(v).strip()] for k, v in data.items() if k and v]
except Exception as e:
    print("load existing failed:", e)

print("existing entries:", len(entries))

# 载入扩充段
extra = []
for mod_name in ("lib_extra_a", "lib_extra_b", "lib_extra_c", "lib_extra_d"):
    ns = {}
    try:
        exec(open(os.path.join(ROOT, mod_name + ".py"), encoding="utf-8").read(), ns)
        text = ns.get("EXTRA_" + mod_name.split("_")[-1].upper(), "")
        for line in text.splitlines():
            line = line.strip()
            if "|" in line:
                p, n = line.split("|", 1)
                if p and n:
                    extra.append([p.strip(), n.strip()])
    except Exception as e:
        print(mod_name, "load failed:", e)
print("extra raw entries:", len(extra))

# 程序化变体：常见子进程名后缀 → 同一显示名
SUFFIXES = ("service", "helper", "update", "crash", "tray", "host", "guard", "protect")
expanded = []
for proc, disp in extra:
    expanded.append([proc, disp])
    lp = proc.lower()
    # 主名本身已是全称时不再造变体
    for sf in SUFFIXES:
        variant = lp + "_" + sf if lp.endswith(("e", "r", "t")) else lp + sf
        expanded.append([variant, disp])

# 合并 + 去重（按进程名小写）
merged = {}
for proc, disp in entries + expanded:
    key = proc.strip().lower()
    if key and key not in merged:
        merged[key] = [proc.strip(), disp.strip()]

final_list = sorted(merged.values(), key=lambda x: x[0].lower())
print("final entries:", len(final_list))

# 写回三副本
for path in COPIES:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(final_list, f, ensure_ascii=False, indent=1)
        print("written:", path, os.path.getsize(path))
    except Exception as e:
        print("write failed:", path, e)
