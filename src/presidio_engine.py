"""
presidio_engine.py — Microsoft Presidio NLP-based PII Anonymizer

Reads raw text from stdin, runs Presidio's AnalyzerEngine and AnonymizerEngine
over it, and writes the anonymized text to stdout.

Prerequisites:
  pip install presidio-analyzer presidio-anonymizer
  python -m spacy download en_core_web_lg
"""

import sys

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
except ImportError:
    # If Presidio is not installed, echo the input unchanged and exit
    # with a special code so the TypeScript bridge knows to fall back.
    sys.stdout.write(sys.stdin.read())
    sys.exit(2)


def main() -> None:
    raw_text = sys.stdin.read()

    if not raw_text.strip():
        sys.stdout.write(raw_text)
        return

    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    # Analyze for a broad set of PII entity types
    results = analyzer.analyze(
        text=raw_text,
        language="en",
        entities=[
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "CRYPTO",
            "IP_ADDRESS",
            "IBAN_CODE",
            "NRP",
            "LOCATION",
            "DATE_TIME",
            "US_SSN",
            "US_DRIVER_LICENSE",
            "US_BANK_NUMBER",
            "US_PASSPORT",
            "US_ITIN",
            "MEDICAL_LICENSE",
            "URL",
        ],
    )

    anonymized = anonymizer.anonymize(text=raw_text, analyzer_results=results)
    sys.stdout.write(anonymized.text)


if __name__ == "__main__":
    main()
