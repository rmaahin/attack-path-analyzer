import argparse
import OTXv2
from tqdm import tqdm
from src.config import OTX_API_KEY
from src.database.connector import db

class OTXLoader:
    '''
        Loads OTX pulse data into our graph database.
    '''

    def __init__(self, search_keyword: str, max_pulses: int):
        self.search_keyword = search_keyword
        self.max_pulses = max_pulses
        self.otx = OTXv2.OTXv2(OTX_API_KEY)

        if not OTX_API_KEY:
            raise ValueError("OTX_API_KEY is missing!") 

    def load_otx_pulses(self): 

        clean_search_keyword = self.search_keyword.strip().lower()
        print(f"Searching the OTX database for keyword: {self.search_keyword} ...")
        pulse_results = self.otx.search_pulses(self.search_keyword, max_results=self.max_pulses).get('results', [])

        if not pulse_results:
            print("No pulses found.")
            return
        
        print(f"Found {len(pulse_results)} pulses. Syncing to graph...")

        driver = db.get_driver()
        with driver.session(database="neo4j") as session:
            for pulse in tqdm(pulse_results, desc='Processing pulses...'):

                pulse_id = pulse.get('id')
                author_name = pulse.get('author_name')
                pulse_name = pulse.get('name')
                created = pulse.get('created')
                pulse_description = pulse.get('description')

                if pulse_description is None:
                    pulse_description = ""

                if not pulse_id:
                    continue
                
                if (clean_search_keyword in pulse_name.lower()) or (clean_search_keyword in pulse_description.lower()):
                    query = """
                    MERGE (p: Pulse {pulse_id: $pulse_id})
                    SET p.name = $pulse_name,
                        p.author_name = $author_name,
                        p.created = $created,
                        p.description = $description
                    """
                    session.run(query, pulse_id=pulse_id, pulse_name=pulse_name, author_name=author_name, created=created, description=pulse_description)

                    # Linking pulses to group nodes from mitre attack 
                    pulse_group_query = """
                    MATCH (p: Pulse {pulse_id: $pulse_id})
                    MATCH (g: Group) WHERE toLower(g.name) CONTAINS $keyword
                    MERGE (p)-[:ATTRIBUTED_TO]->(g)        
                    RETURN g.name as matched_name
                    """
                    pulse_group_query_result = session.run(pulse_group_query, pulse_id=pulse_id, keyword=clean_search_keyword)
                    if pulse_group_query_result.peek():
                        tqdm.write(f"Linked to Group: {pulse_group_query_result.single()['matched_name']}")

                    # Linking pulses to malware nodes from mitre attack
                    pulse_malware_query = """
                    MATCH (p: Pulse {pulse_id: $pulse_id})
                    MATCH (m: Malware) WHERE toLower(m.name) CONTAINS $keyword
                    MERGE (p)-[:TARGETS_VIA_MALWARE]->(m)
                    RETURN m.name as matched_name
                    """
                    pulse_malware_query_result = session.run(pulse_malware_query, pulse_id=pulse_id, keyword=clean_search_keyword)
                    if pulse_malware_query_result.peek():
                        tqdm.write(f"Linked to Malware: {pulse_malware_query_result.single()['matched_name']}")

                    indicators_results = self.otx.get_pulse_indicators(pulse_id)
                    for ioc in indicators_results:
                        ioc_type = ioc.get('type')
                        ioc_value = ioc.get('indicator')

                        if not ioc_type:
                            continue

                        if ioc_type == 'domain' or ioc_type == 'hostname':
                            domain_ioc_query = """
                            MATCH (p: Pulse {pulse_id: $pulse_id})
                            MERGE (d: Domain {domain_name: $domain_name})
                            MERGE (p)-[:HAS_INDICATOR]->(d)
                            """
                            session.run(domain_ioc_query, pulse_id=pulse_id, domain_name=ioc_value)
                        elif ioc_type == 'IPv4' or ioc_type == 'IPv6':
                            ip_ioc_query = """
                            MATCH (p: Pulse {pulse_id: $pulse_id})
                            MERGE (i: IP {ip_address: $ip_address})
                            MERGE (p)-[:HAS_INDICATOR]->(i)
                            """
                            session.run(ip_ioc_query, pulse_id=pulse_id, ip_address=ioc_value)
                        elif 'FileHash' in ioc_type:
                            filehash_ioc_query = """
                            MATCH (p: Pulse {pulse_id: $pulse_id})
                            MERGE (f: FileHash {filehash: $filehash})
                            MERGE (p)-[:HAS_INDICATOR]->(f)
                            """
                            session.run(filehash_ioc_query, pulse_id=pulse_id, filehash=ioc_value)
                        else:
                            continue
        db.close()

        is_closed = db.verify_closed()

        if is_closed:
            print("Confirmed: Driver is closed.")
        else:
            print("Warning: Driver is still open!")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Connecting OTX pulses to MITRE nodes.")
    parser.add_argument("search_keyword", metavar="search-keyword", help="Keyword to be searched for in the OTX pulse library.")
    parser.add_argument("-mp", "--max_pulses", help="Maximum number of pulses to be considered from the search results. Default is 100.", default=100, type=int)
    args = parser.parse_args()

    search_keyword = args.search_keyword
    max_pulses = args.max_pulses
    otx_loader = OTXLoader(search_keyword, max_pulses)
    otx_loader.load_otx_pulses()

    
