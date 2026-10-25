import sys
import pandas as pd

df = pd.read_csv("results.csv")
df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True)
serious = df[df["Level"].isin(["critical", "crit", "high"])]

if len(sys.argv) < 2:
    # No argument: list the log files with the most varied serious alerts
    summary = (serious.groupby("EvtxFile")
               .agg(alerts=("RuleTitle", "size"),
                    different_detections=("RuleTitle", "nunique"),
                    computer=("Computer", "first"))
               .sort_values("different_detections", ascending=False)
               .head(15))
    pd.set_option("display.width", 250)
    pd.set_option("display.max_colwidth", 90)
    print(summary.to_string())
else:
    # Argument: show the timeline for one log file
    name = sys.argv[1]
    t = serious[serious["EvtxFile"].str.contains(name, case=False, na=False, regex=False)]
    t = t.sort_values("Timestamp")
    cols = ["Timestamp", "Computer", "Level", "RuleTitle", "MitreTags"]
    pd.set_option("display.width", 250)
    pd.set_option("display.max_colwidth", 70)
    print(t[cols].to_string(index=False))
    t[cols].to_csv("incident_timeline.csv", index=False)
    print("\nSaved to incident_timeline.csv")