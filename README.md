# PivotProtect - AI powered Intrusion Detection & Prevention System (IDPS)
A simple academic project that detects suspicious network behavior using static log analysis and live packet capturing.
The system uses Python, Tkinter, Scapy, and basic DSA techniques (HashMap, Trie, Graph + simple classifiers).

# Frameworks / Libraries 
- Python 3
- Tkinter (GUI)
- Scapy (Live packet capture)
- NumPy / Pandas (small preprocessing)
- Joblib (loading trained model)

# File Structure
PivotProtect/  
│  
├── data/  
│   ├── sample_static_logs.txt  
│   └── dataset.csv  
│  
├── src/  
│   ├── gui/  
│   │   └── main_gui.py  
│   │  
│   ├── static_analysis/  
│   │   ├── parser.py  
│   │   ├── dsa_structures.py  
│   │   └── static_detector.py  
│   │  
│   ├── live_capture/  
│   │   ├── packet_sniffer.py  
│   │   └── live_detector.py  
│   │  
│   ├── models/  
│   │   ├── naive_bayes.py  
│   │   └── trained_model.pkl  
│   │  
│   └── main.py  
│  
└── README.md  

------------------------------
line onwards for our eyes only

## Work Division 

# Nabiha – Static Analysis
- Parsing log files  
- Implementing DSA structures (HashMap, Trie, Graph)  
- Static anomaly detection  
- Function: run_static_analysis(filepath)  

# Samrah – Live Capture + GUI
- Live packet sniffing with Scapy  
- Real-time detection integration  
- Tkinter GUI (mode selection, logs, alerts)  
- Main program launcher (main.py)  

## Timeline

# Day 1 — Setup & Basic Structure
  Nabiha (Static Analysis)  
    - Create sample static log file  
    - Build basic file parser  
    - Implement initial DSA structures:  
        HashMap skeleton  
        Trie skeleton  

  Samrah (Live Capture + GUI)  
    - Create basic Tkinter window layout  
    - Add Start/Stop buttons (no functionality yet)  
    - Add scrolling log area  
    - Install + configure Scapy environment  

# Day 2 — Core Functionality
  Nabiha  
    - Complete static detection rules  
    - Integrate HashMap, Trie, Graph  
    - Test static detection using sample logs  

  Samrah  
    - Implement real-time packet capture (packet_sniffer.py)  
    - Implement live detection logic (live_detector.py)  
    - Connect GUI buttons to:  
        run_static_analysis(filepath) --> nabiha ka function  
    - Start/Stop live capture  
    - Display outputs in GUI log panel  

# Day 3 — Integration, Testing, Polishing
  Nabiha  
    - Finalize output formatting for static results  
    - Clean and optimize static detection  
    - Help with testing + preparing demo  
  
  Samrah  
    - Add threat alerts (popup + colored status indicator)  
    - Complete full integration via main.py  
    - Final GUI polishing
    - Write README + finalize project demo  
