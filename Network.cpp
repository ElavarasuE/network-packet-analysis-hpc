#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <omp.h>
#include <chrono>

using namespace std;
using namespace chrono;

/* ================= Packet Structure ================= */
struct Packet {
    int src_port;
    int dst_port;
    int protocol;
    double syn_flag;
    double flow_packets_per_sec;
    double pkt_len_variance;

    string app_protocol;
    string traffic_type;
};

/* ================= Protocol Classification ================= */
string classify_protocol(const Packet &p) {
    if (p.protocol == 6) {  // TCP
        if (p.dst_port == 80 || p.src_port == 80) return "HTTP";
        if (p.dst_port == 443 || p.src_port == 443) return "HTTPS";
        if (p.dst_port == 22 || p.src_port == 22) return "SSH";
        if (p.dst_port == 25 || p.dst_port == 110 || p.dst_port == 143) return "EMAIL";
        return "TCP";
    }
    else if (p.protocol == 17) { // UDP
        if (p.dst_port == 53 || p.src_port == 53) return "DNS";
        return "UDP";
    }
    else if (p.protocol == 1) {
        return "ICMP";
    }
    return "OTHER";
}

/* ================= Traffic Behaviour Classification ================= */
string classify_traffic(const Packet &p,
                        double pkt_rate_threshold,
                        double variance_threshold) {

    if (p.syn_flag > 10)
        return "Suspicious";

    if (p.flow_packets_per_sec > pkt_rate_threshold ||
        p.pkt_len_variance > variance_threshold)
        return "Anomalous";

    return "Normal";
}

/* ================= CSV Reader ================= */
vector<Packet> read_csv(const string &filename) {

    vector<Packet> packets;
    ifstream file(filename);
    string line;

    if (!file.is_open()) {
        cout << "Error opening file!" << endl;
        return packets;
    }

    getline(file, line); // Skip header

    while (getline(file, line)) {
        stringstream ss(line);
        string token;
        Packet p;

        getline(ss, token, ',');               // Src IP (skip)
        getline(ss, token, ','); p.src_port = stoi(token);
        getline(ss, token, ',');               // Dst IP (skip)
        getline(ss, token, ','); p.dst_port = stoi(token);
        getline(ss, token, ','); p.protocol = stoi(token);

        // Skip until SYN Flag Count
        for (int i = 0; i < 44; i++) getline(ss, token, ',');

        getline(ss, token, ','); p.syn_flag = stod(token);

        // Skip until Flow Packets/s
        for (int i = 0; i < 8; i++) getline(ss, token, ',');

        getline(ss, token, ','); p.flow_packets_per_sec = stod(token);
        getline(ss, token, ','); p.pkt_len_variance = stod(token);

        packets.push_back(p);
    }

    return packets;
}

/* ================= MAIN ================= */
int main(int argc, char *argv[]) {

    if (argc < 2) {
        cout << "Usage: ./network_analysis friday.csv" << endl;
        return 1;
    }

    string filename = argv[1];

    vector<Packet> packets = read_csv(filename);
    cout << "Total Records Loaded: " << packets.size() << endl;

    double max_pkt_rate = 0.0;
    double max_variance = 0.0;

    for (auto &p : packets) {
        max_pkt_rate = max(max_pkt_rate, p.flow_packets_per_sec);
        max_variance = max(max_variance, p.pkt_len_variance);
    }

    auto start = high_resolution_clock::now();

    /* ================= OPENMP PARALLEL REGION ================= */
    #pragma omp parallel for
    for (int i = 0; i < packets.size(); i++) {
        packets[i].app_protocol = classify_protocol(packets[i]);
        packets[i].traffic_type =
            classify_traffic(packets[i],
                              max_pkt_rate * 0.99,
                              max_variance * 0.99);
    }

    auto end = high_resolution_clock::now();
    double exec_time =
        duration_cast<milliseconds>(end - start).count() / 1000.0;

    unordered_map<string, int> proto_count, traffic_count;

    for (auto &p : packets) {
        proto_count[p.app_protocol]++;
        traffic_count[p.traffic_type]++;
    }

    cout << "\n=== Application Protocol Distribution ===\n";
    for (auto &kv : proto_count)
        cout << kv.first << " : " << kv.second << endl;

    cout << "\n=== Traffic Behaviour Distribution ===\n";
    for (auto &kv : traffic_count)
        cout << kv.first << " : " << kv.second << endl;

    cout << "\nExecution Time (seconds): " << exec_time << endl;
    cout << "OpenMP Threads Used: " << omp_get_max_threads() << endl;

    return 0;
}
