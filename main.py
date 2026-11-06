
"""
main.py - Command-line entry point for LIA-Sec Injection Guard.

Runs an interactive prompt-injection screening demonstration.
"""

import logging

from injection_guard_v2 import InjectionGuard, Verdict


def main():
    """Run the interactive Injection Guard demonstration."""

    logging.basicConfig(
        level=logging.WARNING,
        format="%(message)s",
    )

    guard = InjectionGuard()

    print("=" * 55)
    print("LIA-Sec Injection Guard v2")
    print("Interactive Prompt Security Demo")
    print("Type 'exit' to close the application.")
    print("=" * 55)

    while True:
        try:
            user_input = input("\nEnter text to analyze: ")

            if user_input.strip().lower() in {"exit", "quit"}:
                print("Closing Injection Guard.")
                break

            decision = guard.screen_input(
                user_input,
                source="user",
            )

            print(f"\nVerdict : {decision.action.value.upper()}")
            print(f"Score   : {decision.result.score}")

            if decision.result.findings:
                print("Findings:")
                for finding in decision.result.findings:
                    print(f"  - {finding}")

            if decision.action is Verdict.BLOCK:
                print("\n[BLOCKED] Input rejected by security guard.")
            else:
                print("\n[ACCEPTED FOR FURTHER PROCESSING]")
                print(decision.text)

        except (KeyboardInterrupt, EOFError):
            print("\nClosing Injection Guard.")
            break


if __name__ == "__main__":
    main()
