import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

# Neo4j Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# Validation (Optional but helpful)
if not NEO4J_PASSWORD:
    raise ValueError("NEO4J_PASSWORD not found in .env file!")

if not OTX_API_KEY:
    raise ValueError("OTX API Key not found in .env file!")