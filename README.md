# network-packet-analysis-hpc

# Network Packet Analysis Using HPC

**C-DAC Chennai | Advanced HPC-AI Program | 2025**

## Overview
A high-performance network traffic analysis system built using Python and C++ with OpenMP.
Processes real-world network flow data (CICIDS 2017 dataset) to classify protocols and detect
suspicious/anomalous traffic — designed for SOC environments.

## Features
- Classifies traffic into TCP, UDP, ICMP, HTTP/HTTPS, DNS, SSH, Email protocols
- Detects Normal, Suspicious (SYN flood), and Anomalous traffic behavior
- Parallel processing with OpenMP (C++) and Python multiprocessing
- Achieved 99x speedup: serial 13.96s → parallel 0.14s on 80 CPU cores
- Processed 547,557 network flow records from CICIDS 2017 dataset
- Visualization: protocol distribution charts, traffic behavior pie charts

## Tech Stack
Python | Pandas | NumPy | Matplotlib | Jupyter Notebook | C++ | OpenMP | HPC

## Files
- `Python.ipynb` — Main analysis notebook (data loading, classification, visualization)
- `Network.cpp` — C++ OpenMP parallel implementation
- `CDAC_Final_Project-Network_Packet_Analysis.pdf` — Full project report

## Results
| Method | Execution Time |
|--------|---------------|
| Serial (Python) | 13.96 seconds |
| Parallel (C++ OpenMP, 80 cores) | 0.14 seconds |

## Dataset
CICIDS 2017 — Canadian Institute for Cybersecurity
