import json
from tqdm import tqdm
from src.database.connector import db
from src.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

MITRE_JSON_PATH = "data/mitre/enterprise-attack.json"

class MITRELoader:

    def __init__(self, data_path):
        self.data_path = data_path

    def get_attack_id(self, external_references: list):
        """
            Helper function to extract the attack ID that is usually buried inside the json dict.
        """
        
        for external_reference in external_references:
            if external_reference.get('source_name') == "mitre-attack":
                return external_reference.get('external_id')
        
        return None
            
    def load_mitre_data(self):
        '''
            Data loader function.
        '''

        with open(self.data_path, 'r') as f:
            data = json.load(f)

        driver = db.get_driver()
        with driver.session(database="neo4j") as session:
            stix_objects = data['objects']
            for stix_object in tqdm(stix_objects, desc="Processing objects"):
                if stix_object.get('type') == 'attack-pattern':
                    technique_name = stix_object.get('name')
                    description = stix_object.get('description', "No description.")
                    external_references = stix_object.get('external_references', [])
                    external_id = self.get_attack_id(external_references)

                    # Creating Technique Nodes                
                
                    url = ""
                    if external_references:
                        url = external_references[0].get('url', "")
                        
                    if external_id:
                        query = """
                        MERGE (t: Technique {id: $id})
                        SET t.name = $name,
                            t.description = $desc,
                            t.url = $url
                        """
                        session.run(query, id=external_id, name=technique_name, desc=description, url=url)

                        # Creating Tactice nodes and links
                        kill_chain_phases = stix_object.get('kill_chain_phases', [])
                        for kill_chain_phase in kill_chain_phases:
                            phase_name = kill_chain_phase['phase_name']

                            query = """
                            MERGE (tac:Tactic {name: $tactic_name})
                            WITH tac
                            MATCH (t:Technique {id: $tech_id})
                            MERGE (tac)-[:HAS_TECHNIQUE]->(t)
                            """
                            session.run(query, tactic_name=phase_name, tech_id=external_id)
        db.close()

        is_closed = db.verify_closed()

        if is_closed:
            print("Confirmed: Driver is closed.")
        else:
            print("Warning: Driver is still open!")

if __name__ == "__main__":
       mitre_dataloader = MITRELoader(data_path = MITRE_JSON_PATH) 
       mitre_dataloader.load_mitre_data()
    
        