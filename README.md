# SentinelGraph: 

A cybersecurity intelligence platform that analyzes attack paths by integrating MITRE ATT&CK framework, threat intelligence from AlienVault OTX, and security event logs into a Neo4j graph database. The system uses LLM-powered agents to provide natural language querying capabilities for SOC analysts.

## Overview

This project helps security operations teams visualize and understand attack paths by:
- Loading MITRE ATT&CK framework data (tactics, techniques, groups, malware)
- Ingesting threat intelligence from AlienVault OTX pulses
- Processing security event logs (Splunk BOTS dataset)
- Creating a unified knowledge graph in Neo4j
- Providing natural language query interface powered by LangChain and Groq

## Architecture

```
┌─────────────────┐
│  Data Sources   │
│  - MITRE ATT&CK │
│  - OTX Pulses   │
│  - Splunk Logs  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Data Loaders   │
│  - mitre_loader │
│  - otx_loader   │
│  - splunk_loader│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Neo4j Graph   │
│   Knowledge DB  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LLM Agent      │
│  (Graph Query)  │
└─────────────────┘
```

## 📊 Graph Schema

The knowledge graph contains the following node types and relationships:

### Nodes
- **Tactic**: MITRE ATT&CK tactics (e.g., Initial Access, Execution)
- **Technique**: MITRE ATT&CK techniques (e.g., T1566 - Phishing)
- **Group**: Threat actor groups (e.g., APT28, Sofacy)
- **Malware**: Malware families (e.g., Emotet, TrickBot)
- **Pulse**: OTX threat intelligence pulses
- **Domain**: Malicious domains
- **IP**: IP addresses (indicators of compromise)
- **FileHash**: File hashes (MD5, SHA-256)
- **Device**: Compromised devices/hosts
- **User**: User accounts
- **Process**: Executed processes

### Relationships
- `(Tactic)-[:HAS_TECHNIQUE]->(Technique)`
- `(Group)-[:USES]->(Technique)`
- `(Group)-[:USES]->(Malware)`
- `(Pulse)-[:ATTRIBUTED_TO]->(Group)`
- `(Pulse)-[:TARGETS_VIA_MALWARE]->(Malware)`
- `(Pulse)-[:HAS_INDICATOR]->(Domain|IP|FileHash)`
- `(Device)-[:COMMUNICATED_WITH]->(IP)`
- `(Device)-[:RAN_PROCESS]->(Process)`
- `(User)-[:LOGGED_ON_TO]->(Device)`

## 🚀 Getting Started

### Prerequisites

- Docker and Docker Compose
- Neo4j database (running on port 7687)
- Python 3.12+
- CUDA-compatible GPU (optional, for enhanced performance)

### Environment Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd attack-path-analyzer
```

2. Create a `.env` file in the root directory:
```env
NEO4J_URI=neo4j://127.0.0.1:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password_here
OTX_API_KEY=your_otx_api_key_here
GROQ_API_KEY=your_groq_api_key_here
```

3. Download MITRE ATT&CK data:
```bash
mkdir -p data/mitre
curl -o data/mitre/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

### Installation

#### Using Docker (Recommended)

1. Build the Docker image:
```bash
docker build -t attack-path-analyzer .
```

2. Run the container:
```bash
docker run --gpus all --rm -it \
  -v $(pwd):/mnt \
  -v $(pwd)/data:/mnt/data \
  --name apa
  attack-path-analyzer
```

#### Local Installation

1. Create a virtual environment:
```bash
python3 -m venv env
source env/bin/activate 
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Data Loading

### 1. Load MITRE ATT&CK Framework

```bash
python -m src.ingestion.mitre_loader
```

This loads:
- Tactics, Techniques, Groups, and Malware
- Links relationships between them

### 2. Load OTX Threat Intelligence

```bash
python -m src.ingestion.otx_loader "search_keyword" --max_pulses 100
```

Parameters:
- `search_keyword`: Keyword to search in OTX (e.g., malware name, threat actor)
- `--max_pulses` or `-mp`: Maximum number of pulses to load (default: 100)

This loads:
- OTX pulses matching the search keyword
- Associated indicators (domains, IPs, file hashes)
- Links to MITRE groups and malware

### 3. Load Security Event Logs

```bash
python -m src.ingestion.splunk_bots_loader
```

This loads:
- Device information
- User authentication events
- Process execution logs
- Network communication events

## Querying the Knowledge Graph

### Using the LLM Agent

```python
# Ask natural language questions
question = "Which devices are affected by Emotet malware and what IPs did they communicate with?"
answer = agent.graph_query(question)
print(answer)
```

### Example Queries

1. **Find malware associated with an IP:**
   - "What malware is associated with IP 192.168.1.100?"

2. **Find affected devices:**
   - "Show me all devices that communicated with malicious IPs"

3. **Track attack paths:**
   - "What's the full attack path for Emotet malware?"

4. **User threat analysis:**
   - "What threats are targeting user 'alice'?"

5. **Technique usage by groups:**
   - "What techniques does APT28 use?"

## 📁 Project Structure

```
attack-path-analyzer/
├── app/                      # Application code (future)
│   ├── main.py
│   └── utils.py
├── data/                     # Data storage (gitignored)
│   ├── mitre/               # MITRE ATT&CK data
│   └── splunk_bots/         # Security event logs
├── notebooks/               # Jupyter notebooks for testing
│   ├── mitre-loader-test.ipynb
│   └── otx-loader-test.ipynb
├── src/
│   ├── agent/               # LLM agent components
│   │   └── graph_tools.py  # Graph querying with LangChain
│   ├── database/            # Database connections
│   │   ├── connector.py    # Neo4j connection manager
│   │   └── schema.py
│   ├── ingestion/           # Data loaders
│   │   ├── mitre_loader.py
│   │   ├── otx_loader.py
│   │   └── splunk_bots_loader.py
│   └── config.py           # Configuration management
├── .dockerignore
├── .gitignore
├── Dockerfile
├── LICENSE                  # MIT License
├── README.md
└── requirements.txt
```

## Configuration

### Neo4j Configuration

Ensure Neo4j is running with:
- Bolt protocol enabled (port 7687)
- APOC procedures installed 
- Sufficient memory allocation for large graphs

### API Keys

1. **OTX API Key**: Register at [AlienVault OTX](https://otx.alienvault.com/)
2. **Groq API Key**: Get your key from [Groq Console](https://console.groq.com/)

## 📊 Example Use Cases

### 1. Incident Response
Quickly trace the attack path from initial compromise to lateral movement:
```python
question = "Show me the complete attack chain for devices that communicated with IP 10.0.0.5"
```

### 2. Threat Hunting
Identify potential threats based on known TTPs:
```python
question = "Which devices show signs of techniques used by APT28?"
```

### 3. Indicator Enrichment
Get context about suspicious indicators:
```python
question = "What do we know about domain evil-domain.com?"
```

### 4. Attack Surface Analysis
Understand your exposure:
```python
question = "Show me all external IPs that internal devices communicated with"
```

## Contact

For questions, issues, or suggestions, please open an issue on GitHub or reach out to me on rmaahin2000@gmail.com!

---

**Built with ❤️ for the cybersecurity community**
