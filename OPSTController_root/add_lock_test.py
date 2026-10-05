# -*- coding: utf-8 -*-
import json
p = r"C:\Users\TXZDM\Desktop\OPSTcontroller_Releasedontaction\userdata\config.json"
cfg = json.load(open(p, encoding="utf-8"))
locked = cfg.setdefault("locked_defaults", {})
locked.pop(".xlock", None)
locked[".m4a"] = "WMP11.AssocFile.M4A"
json.dump(cfg, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
print("updated:", locked)
