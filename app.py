import json
from pathlib import Path
from typing import Any, Dict, List

from mailsentry.engine import evaluate_email, scan_folder
from mailsentry.fail_safe import unverified_result

import streamlit as st

from mailsentry.storage import EvidenceStore
from mailsentry.trust_lifecycle import TrustLifecycleManager


def _render_ai_report(report: Dict[str, Any]) -> None:
    ai_details = report.get("ai_details") or {}
    tactics = ai_details.get("detected_tactics") or ["None detected"]
    risk_score = int(report.get("ai_risk_score", 0))
    is_phishing = bool(ai_details.get("is_phishing", False))

    if risk_score >= 80:
        confidence = "High"
    elif risk_score >= 50:
        confidence = "Medium"
    else:
        confidence = "Low"

    category = "High-risk phishing attempt" if is_phishing else "Benign or low-risk message"

    st.markdown("#### AI Threat Analysis Report")
    st.markdown(f"**Threat Category:** {category}")
    st.markdown(f"**Confidence Level:** {confidence} ({risk_score}/100)")

    st.markdown("**Detected Phishing Tactics**")
    for tactic in tactics:
        st.markdown(f"- 🛑 {tactic}")

    st.markdown("**Detailed AI Reasoning**")
    st.info(ai_details.get("reasoning") or "No reasoning available")

    st.markdown("**Recommended SOC Remediation Steps**")
    remediation_steps = [
        "Quarantine the message and preserve headers, attachments, and URLs for forensic review.",
        "Validate sender authentication records (SPF, DKIM, DMARC) and review the sending infrastructure.",
        "Search the SIEM or email gateway logs for similar messages, sender patterns, or related domains.",
        "Notify the affected user and escalate to identity protection if credentials were entered or links were clicked.",
    ]
    for step in remediation_steps:
        st.markdown(f"- ✅ {step}")

st.set_page_config(page_title="MailSentry ESG", page_icon="🛡️", layout="wide")

PROTECTED_DOMAIN = "securecorp.example"
PROTECTED_PERSONNEL = [
    {"name": "Ahmed Al-Mansoor", "role": "CEO", "email": "ceo@securecorp.example"},
    {"name": "Sara Al-Otaibi", "role": "CFO", "email": "cfo@securecorp.example"},
    {"name": "Mona Al-Ghamdi", "role": "HR Director", "email": "hr@securecorp.example"},
    {"name": "Khalid Rahman", "role": "Sr. Security Analyst", "email": "k.rahman@securecorp.example"},
]

SAMPLES_DIR = Path("samples")
HISTORY_STORE = EvidenceStore("history.json")
TRUST_MANAGER = TrustLifecycleManager("trust_lifecycle.json")


def load_sample_files() -> List[Path]:
    if not SAMPLES_DIR.exists():
        return []
    return sorted(SAMPLES_DIR.glob("*.eml"))


def run_evaluation(path: str) -> Dict[str, Any]:
    try:
        return evaluate_email(
            path,
            internal_names=[person["name"] for person in PROTECTED_PERSONNEL],
            internal_titles=[person["role"] for person in PROTECTED_PERSONNEL],
            internal_domains=[PROTECTED_DOMAIN],
        )
    except Exception as exc:
        return unverified_result("dashboard email analysis", exc)


def render_dashboard() -> None:
    st.title("MailSentry Enterprise Email Security Gateway")
    st.caption("Zero-trust email protection platform for phishing, spoofing, and malicious message containment")

    st.sidebar.header("Protected Profile")
    st.sidebar.markdown(f"**Domain:** {PROTECTED_DOMAIN}")
    for person in PROTECTED_PERSONNEL:
        st.sidebar.write(f"- {person['name']} ({person['role']}) — {person['email']}")

    sample_files = load_sample_files()
    selected_path = None
    batch_mode = st.checkbox("Analyze a folder of .eml files", value=False)

    if batch_mode:
        folder_path = st.text_input("Folder path", value=str(SAMPLES_DIR))
        if st.button("Run Batch Scan"):
            with st.spinner("Scanning folder..."):
                results = scan_folder(folder_path, internal_names=[person["name"] for person in PROTECTED_PERSONNEL], internal_titles=[person["role"] for person in PROTECTED_PERSONNEL], internal_domains=[PROTECTED_DOMAIN])
            st.success(f"Processed {len(results)} messages")
            st.dataframe(
                [
                    {
                        "subject": item.get("subject", "No subject"),
                        "from": item.get("from_address", "Unknown"),
                        "decision": item.get("decision", "UNKNOWN"),
                        "risk_score": item.get("risk_score", 0),
                        "reason": item.get("reason", "No reason"),
                    }
                    for item in results
                ],
                use_container_width=True,
            )
    else:
        if sample_files:
            labels = [p.name for p in sample_files]
            selected_name = st.selectbox("Select a sample email", labels)
            selected_path = str(SAMPLES_DIR / selected_name)
        else:
            uploaded = st.file_uploader("Upload an .eml file", type=["eml"])
            if uploaded is not None:
                temp_path = Path("temp_upload.eml")
                temp_path.write_bytes(uploaded.getvalue())
                selected_path = str(temp_path)

        if selected_path:
            with st.spinner("Analyzing email..."):
                report = run_evaluation(selected_path)

            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("Decision", report.get("decision", "UNKNOWN"), help="Final disposition of the message")
            col2.metric("Risk Score", f"{report.get('risk_score', report.get('ai_risk_score', 0))}/100")
            col3.metric("SPF", "PASS" if report.get("spf_pass") else "FAIL")
            col4.metric("Spoofing", "YES" if report.get("spoofed") else "NO")
            col5.metric("AI Flag", "YES" if report.get("ai_is_phishing") else "NO")

            st.markdown("### AI Analysis")
            _render_ai_report(report)

            st.markdown("### Inspection Breakdown")
            lifecycle = report.get("trust_lifecycle") or {}
            st.markdown("#### Trust Lifecycle")
            if lifecycle:
                trust_state = lifecycle.get("trust_state", "unknown")
                transition = lifecycle.get("transition_reason") or "initial"
                if trust_state == "compromised":
                    st.error(f"Trust State: {trust_state.title()} | Transition: {transition}")
                elif trust_state == "suspicious":
                    st.warning(f"Trust State: {trust_state.title()} | Transition: {transition}")
                else:
                    st.success(f"Trust State: {trust_state.title()} | Transition: {transition}")
            else:
                st.info("Trust lifecycle not available")

            st.markdown("#### Email Metadata")
            st.write({
                "subject": report.get("subject"),
                "from": report.get("from_address"),
                "decision": report.get("decision"),
                "risk_score": report.get("risk_score"),
                "reason": report.get("reason"),
            })

            st.markdown("#### Narrative")
            st.info(report.get("threat_narrative", "No narrative available"))

            if report.get("policy_hits"):
                st.markdown("**Policy Rule Hits**")
                for hit in report.get("policy_hits", []):
                    st.markdown(f"- {hit.get('rule')} [{hit.get('severity')}] — {hit.get('detail')}")

            st.markdown("#### Full Analysis JSON")
            st.code(json.dumps(report, indent=2, ensure_ascii=False), language="json")

            st.markdown("#### Incident Timeline")
            message_id = report.get("trust_lifecycle", {}).get("message_id") or report.get("subject")
            timeline = TRUST_MANAGER.get_timeline(message_id) if message_id and hasattr(TRUST_MANAGER, 'get_timeline') else []
            if timeline:
                for entry in timeline:
                    event_label = entry.get("event", "event")
                    state = entry.get("trust_state", "unknown")
                    transition = entry.get("transition_reason") or "initial"
                    st.write(f"- {event_label} → {state.upper()} ({transition})")
            else:
                st.info("No timeline events recorded yet")

            st.markdown("### Quarantine & Response Center")
            if report.get("decision") == "BLOCK":
                st.error(f"Threat quarantined: {report.get('reason')}")
                action_col1, action_col2, action_col3 = st.columns(3)
                with action_col1:
                    st.button("Block Sender Domain / IP", type="primary")
                with action_col2:
                    st.button("Release to Target Inbox")
                with action_col3:
                    if st.button("View Full AI Threat Analysis Report", key="view_ai_report"):
                        st.session_state["show_ai_report"] = True
                if st.session_state.get("show_ai_report"):
                    _render_ai_report(report)
            elif report.get("decision") == "QUARANTINE":
                st.warning(f"Message requires review: {report.get('reason')}")
            else:
                if report.get("verdict") == "UNVERIFIED":
                    st.warning(f"Manual review required: {report.get('details', report.get('reason'))}")
                else:
                    st.success("No quarantine action required")

            st.markdown("### Analysis History")
            history = HISTORY_STORE.list()
            if history:
                st.dataframe(
                    [
                        {
                            "timestamp": item.get("timestamp", "unknown"),
                            "subject": item.get("subject", "No subject"),
                            "decision": item.get("decision", "UNKNOWN"),
                            "risk_score": item.get("risk_score", 0),
                        }
                        for item in reversed(history[-5:])
                    ],
                    use_container_width=True,
                )
            else:
                st.info("No history recorded yet")


if __name__ == "__main__":
    render_dashboard()
