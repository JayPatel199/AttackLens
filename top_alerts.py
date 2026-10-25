import pandas as pd

df = pd.read_csv("results.csv")
serious = df[df["Level"].isin(["critical", "crit", "high"])]

summary = (serious.groupby(["Level", "RuleTitle", "MitreTags"], dropna=False)
           .size().reset_index(name="Count")
           .sort_values(["Level", "Count"], ascending=[True, False]))

pd.set_option("display.max_colwidth", 60)
pd.set_option("display.width", 200)
print(summary.head(30).to_string(index=False))