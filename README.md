# MailSentry Email Security Gateway

MailSentry is a prototype enterprise email security gateway designed to block phishing and spoofing attempts before they reach a user inbox. It combines parsing, sender-authentication checks, identity spoofing detection, optional AI analysis, and a lightweight decision engine.

## Project Structure

- `mailsentry/parser.py` — RFC 822 parsing, header/body extraction, links, attachments
- `mailsentry/dns_checker.py` — SPF, DKIM, DMARC, and identity spoofing checks
- `mailsentry/ai_analyzer.py` — heuristic or LLM-based phishing analysis
- `mailsentry/engine.py` — final PASS/BLOCK decision engine
- `mailsentry/simulator.py` — batch simulation over sample emails
- `mailsentry/dashboard.py` — CLI dashboard for summary and quarantine logs

## Installation

```bash
pip install -r requirements.txt
```

## Run a Single Email Evaluation

```bash
python -m mailsentry.engine sample_phishing.eml --employee-name "Alice Johnson" --internal-domain company.example
```

## Run the Simulation

```bash
python -m mailsentry.simulator --output simulation_results.json
```

## View the Dashboard

```bash
python -m mailsentry.dashboard --report simulation_results.json
```

## Notes

- The prototype uses the standard library `email` parser and optional `dnspython` for DNS-based checks.
- Without an LLM endpoint, the AI layer falls back to deterministic heuristics.
- In a real deployment, the engine would be wired to a mail relay or quarantine store to silently block and isolate messages.
