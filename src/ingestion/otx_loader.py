import OTXv2
from tqdm import tqdm
from src.config import OTX_API_KEY
from src.database.connector import db

class OTXLoader:

    def __init__(self, search_keyword: str, max_pulses: int):
        self.search_keyword = search_keyword
        self.max_pulses = max_pulses
        self.otx = OTXv2.OTXv2(OTX_API_KEY)

        if not OTX_API_KEY:
            raise ValueError("OTX_API_KEY is missing!") 

    def load_otx_pulses(self):
        '''
            OTX data loader function.
        ''' 
        print(f"Searching the OTX database for keyword: {self.search_keyword} ...")
        pulse_results = self.otx.search_pulses(self.search_keyword, max_results=self.max_pulses).get('results', [])

        if not pulse_results:
            print("No pulses found.")
            return
        
        print(f"Found {len(pulse_results)} pulses. Syncing to graph...")

        driver = db.get_driver()
        with driver.session(database="neo4j") as session:
            for pulse in tqdm(pulse_results, desc='Processing pulses...'):
                attack_ids = pulse.get('attack_ids', [])
                if not attack_ids:
                    continue

                pulse_id = pulse.get('id')
                author_name = pulse.get('author_name')
                pulse_name = pulse.get('name')
                created = pulse.get('created')
                
                if pulse_id:
                    query = """
                    MERGE (p: Pulse {pulse_id: $pulse_id})
                    SET p.name = $pulse_name,
                        p.author_name = $author_name,
                        p.created = $created
                    """
                    session.run(query, pulse_id=pulse_id, pulse_name=pulse_name, author_name=author_name, created=created)

                    if attack_ids:
                        tqdm.write(f"Bridge found! Linking '{pulse_name} to {len(attack_ids)} MITRE techniques.")
                        link_to_mitre_query = """
                        MATCH (p: Pulse {pulse_id: $pulse_id})
                        UNWIND $attack_ids AS tech_id
                        MATCH (t: Technique {id: tech_id})
                        MERGE (p)-[:RELATED_TO]->(t)
                        """
                        session.run(link_to_mitre_query, pulse_id=pulse_id, attack_ids=attack_ids)


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
if __name__ == "__main__":

    search_keyword = "Ransomware"
    max_pulses = 100
    otx_loader = OTXLoader(search_keyword, max_pulses)
    otx_loader.load_otx_pulses()

    
