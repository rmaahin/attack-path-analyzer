from neo4j import GraphDatabase
from src.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

class Neo4JConnector:
    def __init__(self):
        self._driver = None

    def get_driver(self):
        '''
            Returns the Neo4j driver, creating it if it doesn't exist.
        '''

        if self._driver is None:
            self._driver = GraphDatabase.driver(
                NEO4J_URI,
                auth = (NEO4J_USER, NEO4J_PASSWORD)
            )

            try:
                self._driver.verify_connectivity()
                print("Successfully connected to Neo4j.")

            except Exception as e:
                print(f"Failed to connect to Neo4j: {e}")
                raise e
            
        return self._driver

    def close(self):
        '''
            Closes the Neo4j driver connection.
        '''

        if self._driver:
            self._driver.close()
            self._driver = None
            print("Neo4j connection closed.")

    def verify_closed(self):
        """
        Verifies if the driver is closed by attempting a connectivity check.
        Returns True if closed, False if still open.
        """
        if self._driver is None:
            return True
            
        try:
            self._driver.verify_connectivity()
            return False
        except Exception:
            return True

db = Neo4JConnector()