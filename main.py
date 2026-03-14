"""
main.py — Interactive demo for the LLM Security Mini-Gateway
Run: python main.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from src.gateway import LLMSecurityGateway


BANNER = """
╔══════════════════════════════════════════════════════╗
║     Presidio-Based LLM Security Mini-Gateway         ║
║        Information Security Assignment 2             ║
╚══════════════════════════════════════════════════════╝
Type your prompt and press Enter. Type 'exit' to quit.
Type 'metrics' to see summary statistics.
"""


def main():
    print(BANNER)
    gateway = LLMSecurityGateway()

    while True:
        try:
            user_input = input("\n[USER] > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[Gateway] Shutting down.")
            break

        if not user_input:
            continue

        if user_input.lower() == "exit":
            print("[Gateway] Goodbye.")
            break

        if user_input.lower() == "metrics":
            m = gateway.get_summary_metrics()
            print("\n[METRICS]")
            for k, v in m.items():
                print(f"  {k}: {v}")
            continue

        result = gateway.process(user_input)

        print(f"\n[DECISION]        {result['decision']}")
        print(f"[INJECTION SCORE] {result['injection_score']:.4f}  ({result['injection_label']})")
        print(f"[PII DETECTED]    {len(result['pii_entities'])} entities")
        if result["pii_entities"]:
            for e in result["pii_entities"]:
                print(f"   - {e['entity_type']} (score={e['score']:.2f}, pos={e['start']}:{e['end']})")
        print(f"[LATENCY]         {result['latency_ms']:.2f} ms")
        print(f"[OUTPUT]\n{result['output']}")


if __name__ == "__main__":
    main()
