import pandas as pd
import streamlit as st

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")
st.title("Threat Detection Dashboard")
st.caption("Hayabusa + custom Sigma-style rules, run on public attack logs (EVTX-ATTACK-SAMPLES)")

LEVELS = ["critical", "high", "medium", "low", "informational"]

@st.cache_data
def load():
    base = pd.read_csv("results.csv")
    base["Source"] = "Hayabusa built-in rules"
    try:
        mine = pd.read_csv("my_results.csv")
        mine["Source"] = "My custom rules"
        df = pd.concat([base, mine], ignore_index=True)
    except FileNotFoundError:
        df = base
    df["Level"] = df["Level"].replace(
        {"crit": "critical", "med": "medium", "info": "informational"})
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True)
    return df

df = load()

st.sidebar.header("Filters")
chosen_levels = st.sidebar.multiselect(
    "Severity", LEVELS, default=["critical", "high", "medium", "low"])
sources = st.sidebar.multiselect(
    "Rule source", sorted(df["Source"].unique()), default=list(df["Source"].unique()))
df = df[df["Level"].isin(chosen_levels) & df["Source"].isin(sources)]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total alerts", len(df))
c2.metric("Computers affected", df["Computer"].nunique())
c3.metric("Unique detections", df["RuleTitle"].nunique())
c4.metric("Critical alerts", int((df["Level"] == "critical").sum()))

left, right = st.columns(2)
with left:
    st.subheader("Alerts by severity")
    sev = df["Level"].value_counts().reindex(LEVELS).dropna()
    st.bar_chart(sev)
with right:
    st.subheader("Top 10 detections")
    st.bar_chart(df["RuleTitle"].value_counts().head(10))

st.subheader("MITRE ATT&CK techniques seen")
if "MitreTags" in df.columns:
    tags = df["MitreTags"].dropna().str.split("¦").explode().str.strip()
    st.bar_chart(tags.value_counts().head(15))

left2, right2 = st.columns(2)
with left2:
    st.subheader("Alerts per computer")
    st.bar_chart(df["Computer"].value_counts().head(10))
with right2:
    st.subheader("Alerts over time (by month)")
    t = df.dropna(subset=["Timestamp"])
    st.line_chart(t.groupby(t["Timestamp"].dt.strftime("%Y-%m")).size())

st.subheader("Alert details")
cols = ["Timestamp", "Level", "RuleTitle", "Computer", "MitreTags", "Details"]
st.dataframe(df[[c for c in cols if c in df.columns]])