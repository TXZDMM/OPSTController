# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r"C:\Users\TXZDM\Desktop\OPSTController-main\OPSTController_root")
import extension_protector as ep

ep.USERDATA_DIR = r"C:\Users\TXZDM\Desktop\OPSTcontroller_Releasedontaction\userdata"
ep.BASELINE_FILE = ep.os.path.join(ep.USERDATA_DIR, "baseline.json")
ep.CONFIG_FILE = ep.os.path.join(ep.USERDATA_DIR, "config.json")
ep.HISTORY_DIR = ep.os.path.join(ep.USERDATA_DIR, "baseline_history")

bm = ep.BaselineManager()
engine = ep.ProtectionEngine(bm)
mm = engine.check_extension(".m4a")
print("mismatches:", [(m[0], m[1], m[2]) for m in mm])
bl = bm.baseline.get(".m4a", {})
for k, v in bl.items():
    if isinstance(v, dict):
        print(k, "->", repr(v.get("value")), v.get("root"))
