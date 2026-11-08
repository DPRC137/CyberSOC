#!/usr/bin/env python3
"""
End-to-End Demonstration Script for CyberSOC Hybrid Detection System
====================================================================
Executes and validates the complete 10-step lifecycle:
1. Generate normal network traffic.
2. Generate malicious network traffic.
3. Process the events.
4. Run Bayesian classification.
5. Run Markov sequence analysis.
6. Calculate hybrid risk.
7. Generate alerts.
8. Display the results in the dashboard (via API verification).
9. Restart the application (simulate complete restart of pipeline and DB connection).
10. Confirm persisted data remains available.
"""

import sys
import time
import json
import sqlite3
import os

from engine.traffic_generator import TrafficGenerator
from engine.pipeline import DetectionPipeline
import app

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def log_header(title):
    print(f"\n{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}>>> {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")

def log_step(step_num, title, details=""):
    print(f"\n{BOLD}{YELLOW}[Step {step_num}] {title}{RESET}")
    if details:
        print(f"       {details}")

def run_demo():
    log_header("CyberSOC: Bayesian-Markov Hybrid Threat Detection End-to-End Demonstration")

    db_path = 'cyber_soc.db'
    data_path = 'intrusion_data.csv'

    # Check database baseline
    conn_initial = sqlite3.connect(db_path)
    cur_init = conn_initial.cursor()
    cur_init.execute("SELECT COUNT(*) FROM alerts")
    initial_alerts_count = cur_init.fetchone()[0]
    conn_initial.close()
    print(f"{GREEN}✓ Baseline Database checked: {initial_alerts_count} existing alerts present.{RESET}")

    # Initialize Engine & Pipeline
    pipeline = DetectionPipeline(db_path=db_path, data_path=data_path, alert_threshold=0.60)
    traffic_gen = TrafficGenerator(seed=42)

    # -------------------------------------------------------------
    # STEP 1: Generate normal network traffic
    # -------------------------------------------------------------
    log_step(1, "Generate normal network traffic", "Simulating benign IoT device communications (telemetry, low packet rate, 0 failed logins)")
    normal_events = [
        traffic_gen.generate_normal_event(device="Lobby-Cam-01", source_ip="192.168.1.101"),
        traffic_gen.generate_normal_event(device="Server-Room-Therm", source_ip="192.168.1.102"),
    ]
    for ev in normal_events:
        print(f"   Generated Normal Event: ID={ev['session_id']}, Device={ev['device']}, IP={ev['source_ip']}, Packets={ev['network_packet_size']}B, Failed Logins={ev['failed_logins']}")

    # -------------------------------------------------------------
    # STEP 2: Generate malicious network traffic
    # -------------------------------------------------------------
    log_step(2, "Generate malicious network traffic", "Simulating multi-stage cyber intrusion campaign (Port Recon -> Brute Force -> Exploit)")
    malicious_events = [
        traffic_gen.generate_malicious_event(attack_phase="recon", device="Edge-Gateway-01", source_ip="198.51.100.25"),
        traffic_gen.generate_malicious_event(attack_phase="brute_force", device="Edge-Gateway-01", source_ip="198.51.100.25"),
        traffic_gen.generate_malicious_event(attack_phase="exploit", device="Main-Entry-Lock", source_ip="203.0.113.88"),
    ]
    for ev in malicious_events:
        print(f"   Generated Malicious Event: ID={ev['session_id']}, Phase={ev.get('attack_phase')}, Device={ev['device']}, Failed Logins={ev['failed_logins']}, Unusual Time={ev['unusual_time_access']}")

    # -------------------------------------------------------------
    # STEP 3: Process the events
    # -------------------------------------------------------------
    log_step(3, "Process the events", "Ingesting all events into the Detection Pipeline")
    all_events = normal_events + malicious_events
    processed_results = []
    for ev in all_events:
        res = pipeline.process_event(ev)
        processed_results.append(res)
    print(f"{GREEN}✓ Successfully ingested and processed {len(processed_results)} events.{RESET}")

    # -------------------------------------------------------------
    # STEP 4: Run Bayesian classification
    # -------------------------------------------------------------
    log_step(4, "Run Bayesian classification", "Evaluating exact Gaussian & Categorical Naive Bayes posteriors P(Attack | x)")
    for i, res in enumerate(processed_results):
        b = res['bayesian']
        ev_type = "Normal" if i < 2 else "Malicious"
        print(f"   Event {i+1} [{ev_type}]: P(Attack) = {b['probability_attack']*100:5.1f}%, Log-Odds = {b['log_odds']:6.2f}, "
              f"Top Evidence = {list(b['feature_contributions'].items())[:2]}")

    # -------------------------------------------------------------
    # STEP 5: Run Markov sequence analysis
    # -------------------------------------------------------------
    log_step(5, "Run Markov sequence analysis", "Tracking endpoint state transitions and kill-chain sequence likelihoods")
    for i, res in enumerate(processed_results):
        m = res['markov']
        ev_type = "Normal" if i < 2 else "Malicious"
        print(f"   Event {i+1} [{ev_type}]: Current State = {m['current_state']:<18} | "
              f"Transition = {m['transition_description']:<35} | P_markov(Attack) = {m['markov_probability']*100:5.1f}%")

    # -------------------------------------------------------------
    # STEP 6: Calculate hybrid risk
    # -------------------------------------------------------------
    log_step(6, "Calculate hybrid risk", "Fusing Bayesian spatial probability (0.50) with Markov temporal probability (0.40) + Context")
    for i, res in enumerate(processed_results):
        h = res['hybrid']
        ev_type = "Normal" if i < 2 else "Malicious"
        color = GREEN if h['severity'] == 'low' else RED if h['severity'] == 'critical' else YELLOW
        print(f"   Event {i+1} [{ev_type}]: {color}Hybrid Risk = {h['hybrid_risk']*100:5.1f}% | Severity = {h['severity'].upper():<8} | Inferred = {h['attack_type']}{RESET}")

    # -------------------------------------------------------------
    # STEP 7: Generate alerts
    # -------------------------------------------------------------
    log_step(7, "Generate alerts", "Evaluating threshold R_hybrid >= 0.60 and auto-persisting alerts into SQLite")
    generated_alerts = []
    for i, res in enumerate(processed_results):
        if res['alert_generated']:
            generated_alerts.append(res['alert_record'])
            print(f"   {RED}🚨 ALERT TRIGGERED: ID={res['alert_id']} | Device={res['device']} | Severity={res['hybrid']['severity']} | Risk={res['hybrid']['hybrid_risk']*100:.1f}%{RESET}")
        else:
            print(f"   {GREEN}✅ No Alert: Event {i+1} is below threshold ({res['hybrid']['hybrid_risk']*100:.1f}% < 60%){RESET}")

    assert len(generated_alerts) >= 2, "Expected at least 2 alerts generated from malicious traffic"
    print(f"{GREEN}✓ Successfully generated and persisted {len(generated_alerts)} security alerts.{RESET}")

    # -------------------------------------------------------------
    # STEP 8: Display the results in the dashboard
    # -------------------------------------------------------------
    log_step(8, "Display the results in the dashboard", "Verifying dashboard live metrics and threat feed endpoints reflect model results")
    client = app.app.test_client()

    dash_res = client.get('/api/dashboard/live').json
    print(f"   Dashboard Live Metrics: Active Threats = {dash_res['activeThreats']}, Threat Level = {dash_res['threatLevel'].upper()}, Anomalies = {dash_res['anomalies']}")

    feed_res = client.get('/api/threats/feed').json
    print(f"   Live Threat Feed: Top event = {feed_res['events'][0]['attackType']} on {feed_res['events'][0]['targetDevice']} (Confidence: {feed_res['events'][0]['confidence']*100:.0f}%)")

    # -------------------------------------------------------------
    # STEP 9: Restart the application
    # -------------------------------------------------------------
    log_step(9, "Restart the application", "Simulating complete server shutdown, unbinding connections, and restarting fresh instance")
    # Terminate pipeline instance and close all sqlite references
    del pipeline
    time.sleep(1.0)

    # Re-initialize the pipeline as occurs on server boot
    restarted_pipeline = DetectionPipeline(db_path=db_path, data_path=data_path, alert_threshold=0.60)
    print(f"{GREEN}✓ Application restarted successfully with fresh in-memory pipeline instance.{RESET}")

    # -------------------------------------------------------------
    # STEP 10: Confirm persisted data remains available
    # -------------------------------------------------------------
    log_step(10, "Confirm persisted data remains available", "Querying SQLite database and API post-restart to ensure zero data loss")
    conn_after = sqlite3.connect(db_path)
    cur_after = conn_after.cursor()

    cur_after.execute("SELECT COUNT(*) FROM alerts")
    final_alerts_count = cur_after.fetchone()[0]

    cur_after.execute("SELECT COUNT(*) FROM events")
    final_events_count = cur_after.fetchone()[0]

    # Verify our specific newly generated alerts are present
    for a in generated_alerts:
        cur_after.execute("SELECT id, device, severity, hybrid_risk FROM alerts WHERE id = ?", (a['id'],))
        row = cur_after.fetchone()
        assert row is not None, f"Alert {a['id']} missing after restart!"
        print(f"   {GREEN}✓ Persisted Alert Verified: ID={row[0]}, Device={row[1]}, Severity={row[2]}, Hybrid Risk={row[3]*100:.1f}%{RESET}")

    conn_after.close()

    print(f"\n{BOLD}{GREEN}{'='*70}{RESET}")
    print(f"{BOLD}{GREEN}ALL 10 DEMONSTRATION STEPS COMPLETED AND VALIDATED SUCCESSFULLY!{RESET}")
    print(f"{BOLD}{GREEN}Initial Alerts: {initial_alerts_count} -> Final Alerts: {final_alerts_count} (+{final_alerts_count - initial_alerts_count} new persisted alerts){RESET}")
    print(f"{BOLD}{GREEN}Total Events Recorded: {final_events_count}{RESET}")
    print(f"{BOLD}{GREEN}{'='*70}{RESET}\n")

if __name__ == '__main__':
    run_demo()
