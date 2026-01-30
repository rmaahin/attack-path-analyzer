import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_neo4j import Neo4jGraph, GraphCypherQAChain
from langchain_core.tools import Tool
from langchain_core.prompts import PromptTemplate
from src.config import GROQ_API_KEY, NEO4J_URI, NEO4J_PASSWORD, NEO4J_USER

class SentinelGraph:
    def __init__(self, model_name, temperature=0):
        
        self.model_name = model_name
        self.temperature = temperature

        self.graph = Neo4jGraph(
            url=NEO4J_URI,
            username=NEO4J_USER,
            password=NEO4J_PASSWORD,
            enhanced_schema=False
        )

        self.llm = ChatGroq(
            model=self.model_name,
            temperature=self.temperature
        )

        CYPHER_GENERATION_TEMPLATE = CYPHER_GENERATION_TEMPLATE = """Task:Generate Cypher statement to query a graph database.
        Instructions:
        Use only the provided relationship types and properties in the schema.
        Do not use any other relationship types or properties that are not provided.
        Do not include any explanations or apologies in your responses.
        Do not include any text except the generated Cypher statement.
        Do not include any markdown formatting or code block delimiters (e.g., ```).
        
        Schema:
        {schema}

        Examples:
        1. How to find malware associated with an IP:
        MATCH (i:IP {{ip_address: '1.2.3.4'}})<-[:HAS_INDICATOR]-(p:Pulse)-[:TARGETS_VIA_MALWARE]->(m:Malware) RETURN m.name

        2. How to find which device communicated with a specific IP:
        MATCH (d:Device)-[r:COMMUNICATED_WITH]->(i:IP {{ip_address: '1.2.3.4'}}) RETURN d.hostname, r.timestamp

        3. How to find all threats targeting a specific user:
        MATCH (u:User {{username: 'alice'}})-[:LOGGED_ON_TO]->(d:Device)-[:COMMUNICATED_WITH]->(i:IP)<-[:HAS_INDICATOR]-(p:Pulse) RETURN p.name

        4. How to find the full attack path for malware Emotet:
        MATCH path = (m:Malware {{name: 'Emotet'}})<-[:TARGETS_VIA_MALWARE]-(p:Pulse)-[:HAS_INDICATOR]->(i:IP)<-[:COMMUNICATED_WITH]-(d:Device) RETURN path

        The question is:
        {question}
        """

        self.CYPHER_PROMPT = PromptTemplate(
            input_variables=["schema", "question"], 
            template=CYPHER_GENERATION_TEMPLATE
        )

        self.cypher_chain = GraphCypherQAChain.from_llm(
            self.llm,
            graph=self.graph,
            verbose=True,
            cypher_prompt=self.CYPHER_PROMPT,
            allow_dangerous_requests=True
        )

    def graph_query(self, question: str) -> str:
        """
        Defines the chain for querying from the grpah knowledge base.

        Args:
            question(str): User's input query
        """
        try:
            response = self.cypher_chain.invoke({'query': question})
            return response['result']
        
        except Exception as e:
            return (f"Unexpected error occurred: {str(e)}")

    def graph_query_tool(self, question) -> str:
        """
        Queries the LLM with the graph knowledge base attached.
        """
        return Tool(
            name="Graph Search",
            func=self.graph_query,
            description="Use this tool to look up data in the Neo4j database. Input: A clear question about users, devices, IPs, or malware."
        )

if __name__=="__main__":

    model_name = "llama-3.3-70b-versatile"
    temperature = 0     # Dont want creativity here

    SentinelGraph_obj = SentinelGraph(model_name=model_name, temperature=temperature)

    test_question = "Can you tell me the devices that are affected my 'Emotet' malware and the IPs they communicated with?"
    print(f"Testing question: {test_question}")

    answer = SentinelGraph_obj.graph_query(test_question)
    print(f"Answer: {answer}")