
from ids.analyzer import analyze_pcap, print_report, generate_insights, print_insights, print_alerts
from ids.detector import run_all_detections

if __name__ == "__main__":
    filepath = "tests/fixtures/sample.pcap"

    stats = analyze_pcap(filepath)
    print_report(stats, filepath)

    insights = generate_insights(stats)
    print_insights(insights)

    detection_results = run_all_detections(filepath)
    print_alerts(detection_results)
