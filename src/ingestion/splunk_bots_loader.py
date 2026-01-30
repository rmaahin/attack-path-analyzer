import json
from tqdm import tqdm
from src.database.connector import db

class SplunkBOTSLoader:
    """
        Loads data from the Splunk BOTS dataset to our graph database.
    """
    def __init__(self, log_path: str):
        self.log_path = log_path

    def load_logs(self):
        with open(self.log_path, 'r') as f:
            splunk_data = json.load(f)

        driver = db.get_driver()

        with driver.session(database="neo4j") as session:
            for log in tqdm(splunk_data, desc='Processing Splunk BOTS logs...'):
                timestamp = log.get('timestamp')
                event_type = log.get('event_type')
                host_name = log.get('host')
                src_ip = log.get('src_ip')
                dst_ip = log.get('dest_ip')
                user = log.get('user')
                description = log.get('description')
                command_line = log.get('command_line')
                process_id = log.get('pid')
                process_name = log.get('process_name')
                network_connection_protocol = log.get('protocol')
                dest_port = log.get('dest_port')
                network_connection_action = log.get('action')

                if not host_name:
                    continue
                
                host_insertion_query = """
                MERGE (d: Device {hostname: $host})
                SET d.src_ip = $src_ip
                """
                session.run(host_insertion_query, host=host_name, src_ip=src_ip)

                if user and event_type=='authentication':
                    user_insertion_query = """
                    MERGE (u: User {username: $user})
                    WITH u
                    MATCH (d: Device {hostname: $host})
                    MERGE (u)-[:LOGGED_ON_TO]->(d) 
                    """  
                    session.run(user_insertion_query, user=user, host=host_name)
                
                if event_type=='process_execution':
                    process_execution_insertion_query = """
                    MERGE (p: Process {process: $process})
                    SET p.command_line = $cmd
                    WITH p
                    MATCH (d: Device {hostname: $host})
                    MERGE (d)-[:RAN_PROCESS]->(p)
                    """
                    session.run(process_execution_insertion_query, process=process_name, host=host_name, cmd=command_line)
                
                if event_type=='network_connection':
                    if dst_ip:
                        network_bridge_query = """
                        MATCH (d: Device {hostname: $host})
                        MERGE (i: IP {ip_address: $dst_ip})
                        MERGE (d)-[r:COMMUNICATED_WITH]->(i)
                        SET r.dest_port = $dest_port,
                            r.protocol = $protocol,
                            r.action = $action,
                            r.timestamp = $timestamp
                        """
                        session.run(network_bridge_query, host=host_name, dst_ip=dst_ip, dest_port=dest_port, protocol=network_connection_protocol, action=network_connection_action, timestamp=timestamp)

        db.close()
        is_closed = db.verify_closed()
        
        if is_closed:
            print("Confirmed: Driver is closed.")
        else:
            print("Warning! Driver is still open.")

if __name__ == "__main__":

    log_path = '/mnt/data/splunk_bots/emotet_sample.json'
    splunk_loader = SplunkBOTSLoader(log_path)
    splunk_loader.load_logs()