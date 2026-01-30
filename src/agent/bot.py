import os
import argparse
from typing import TypedDict, Annotated
from src.config import NEO4J_PASSWORD, NEO4J_URI, NEO4J_USER

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
from langchain_groq import ChatGroq

from src.agent.query_graph import SentinelGraph

class AgentState(TypedDict):
    """
    State of the querying agent. Holds the conversation history.    
    """
    messages: Annotated[list, add_messages]

class QueryingAgent:
    def __init__(self, querying_model_name: str, conversation_model_name: str, temperature: float = 0):
        self.querying_llm = querying_model_name
        self.conversation_llm = conversation_model_name
        self.temperature = temperature

        self.sentinel_obj = SentinelGraph(
            model_name=self.querying_llm, 
            temperature=self.temperature
        )
        self.graph_tool = self.sentinel_obj.graph_query_tool()

        # Did this because langgraph expects a list, even if we just have one tool
        self.tools = [self.graph_tool]
        
        # creating a new instance for a secondary llm to manage conversation flow
        self.conversation_llm = ChatGroq(
            model=self.conversation_llm,
            temperature=self.temperature
        )

        # binding the tools
        self.llm_with_tools = self.conversation_llm.bind_tools(self.tools)

        # initialize memory
        self.memory = MemorySaver()

        self.app = self.build_graph()

    def has_tool_been_called(self, state: AgentState) -> bool:
        """
        Check if the Graph_Search tool has already been called in this conversation turn.
        """
        messages = state["messages"]

        for msg in reversed(messages):
            if isinstance(msg, ToolMessage):
                return True
            if isinstance(msg, HumanMessage):
                break
        
        return False

    def chatbot_node(self, state: AgentState):
        """
        The main node that talks to the querying LLM.
        Takes the history of the conversation, sends it to the LLM and retrieves a response.
        """
        
        tool_already_used = self.has_tool_been_called(state)
        
        if tool_already_used:
            system_instruction = SystemMessage(content=(
                "You are a cybersecurity analyst. The Graph_Search tool has already been executed and returned results."
                "\n\nYour task now:"
                "\n1. Review the tool results that were just returned."
                "\n2. Provide a clear, concise answer to the user's question based on those results."
                "\n3. Do NOT call any tools again - just answer the question."
                "\n4. Be specific and use the actual data from the results."
            ))
        else:
            system_instruction = SystemMessage(content=(
                "You are a cybersecurity analyst with access to a graph database via the 'Graph_Search' tool."
                "\n\nYour task:"
                "\n1. Use the Graph_Search tool to query the database for the requested information."
                "\n2. Call the tool once with a clear question."
                "\n3. Wait for the results before answering."
            ))
        
        messages = [system_instruction] + state["messages"]
        response = self.llm_with_tools.invoke(messages)
        

        if tool_already_used and response.tool_calls:
            print("Tool already executed - preventing redundant call")
            response.tool_calls = []
        
        return {"messages": [response]}
    
    def should_continue(self, state: AgentState):
        """
        Custom logic to decide next step.
        If the last message has a tool call -> Run Tool.
        If the last message has text -> END.
        """
        messages = state["messages"]
        last_message = state["messages"][-1]
        
        # If the LLM wants to run a tool, let it
        if last_message.content and len(last_message.content.strip()) > 0:
            return END
        
        if last_message.tool_calls:
            return "tools"
        
        # Otherwise, if it has content, we are done. Stop the loop.
        return END
    
    def build_graph(self):
        workflow = StateGraph(AgentState)
        workflow.add_node("chatbot", self.chatbot_node)
        workflow.add_node("tools", ToolNode(self.tools))

        workflow.set_entry_point("chatbot")

        workflow.add_conditional_edges(
            "chatbot",
            self.should_continue,
            {
                "tools": "tools",  
                END: END          
            }
        )

        workflow.add_edge("tools", "chatbot")

        return workflow.compile(checkpointer=self.memory)

if __name__=="__main__":

    parser = argparse.ArgumentParser(description="SentinelGraph: Queries the Graph knowledge base to figure out cyber attack paths.")
    # llama-3.3-70b-versatile
    parser.add_argument("querying_llm", metavar="querying-llm", help="The LLM you want to use for querying the graph knowledge base.")
    # llama-3.1-8b-instant
    parser.add_argument("conversation_llm", metavar="convo-llm", help="The LLM you want to use for managing the conversation and tool calling.")
    parser.add_argument("-t", "--temp", help="Temperature parameter for the LLMs. Default is 0.", default=0, type=float)
    args = parser.parse_args()

    querying_model_name = args.querying_llm
    conversation_model_name = args.conversation_llm
    temperature = args.temp

    agent = QueryingAgent(querying_model_name=querying_model_name, conversation_model_name=conversation_model_name, temperature=temperature)

    # session ID
    config = {"configurable": {"thread_id": "1"}}

    test_question = "What's the full attack path for Emotet malware?"
    print(f"Testing question: {test_question}")

    events = agent.app.stream(
        {"messages": [HumanMessage(content=test_question)]},
        config,
        stream_mode="values"    # streaming every step of the thought process and tool calling
    )

    for event in events:
        if "messages" in event:
            last_msg = event["messages"][-1]
            if last_msg.content:
                print(f"AI: {last_msg.content}")