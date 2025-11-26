#!/usr/bin/env python3
"""
AI Assistant Module for WiFi Penetration Testing Tool
Provides real-time assistance for penetration testing using AI models
"""

import os
import json
import time
import threading
import traceback
from typing import List, Dict, Any, Optional, Callable

# Try to import OpenAI for main API access
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("OpenAI module not available, falling back to local models if available")

# Try to import for local AI processing if OpenAI not available
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    LOCAL_AI_AVAILABLE = True
except ImportError:
    LOCAL_AI_AVAILABLE = False
    print("Transformers/Torch not available, local AI processing disabled")

class AIAssistant:
    """AI Assistant for WiFi Penetration Testing Tool
    
    Features:
    - Real-time assistance for penetration testing
    - Answers questions about tool usage and network security
    - Helps with error diagnosis and troubleshooting
    - Can use either OpenAI API or local models
    """
    
    def __init__(self, use_openai=True, api_key=None, log_callback=None):
        """Initialize the AI Assistant
        
        Args:
            use_openai: Whether to use OpenAI API (if False, use local model)
            api_key: OpenAI API key
            log_callback: Callback function for logging messages
        """
        self.use_openai = use_openai
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.log_callback = log_callback
        self.client = None
        self.local_model = None
        self.local_tokenizer = None
        self.conversation_history = []
        self.model_name = "gpt-4o" if use_openai else "local"
        self.max_context_length = 16000  # Token limit for conversation history
        
        # System message that defines the assistant's behavior
        self.system_message = """
        You are an expert AI assistant integrated into a WiFi Penetration Testing Tool.
        Your primary role is to assist with wireless security testing, network penetration,
        and security analysis.
        
        ## Your capabilities include:
        1. Explaining penetration testing concepts and methodologies
        2. Guiding users through the proper use of the tool's features
        3. Helping diagnose and troubleshoot errors or failed commands
        4. Suggesting next steps in a penetration testing workflow
        5. Explaining security vulnerabilities and their implications
        6. Providing context on output from security tools (nmap, aircrack, etc.)
        
        ## Important guidelines:
        - Keep responses focused on ethical security testing and network defense
        - Explain technical concepts clearly but accurately
        - When discussing attacks, always frame them in the context of authorized testing
        - Provide specific, actionable advice when troubleshooting
        - If you don't know something, be honest about limitations
        - Never encourage illegal activities or unauthorized access
        
        The user is a security professional using this tool for legitimate security testing.
        Give them expert-level guidance.
        """
        
        # Initialize the appropriate AI backend
        self.initialize_ai()
    
    def initialize_ai(self):
        """Initialize the AI model based on configuration"""
        if self.use_openai:
            if OPENAI_AVAILABLE and self.api_key:
                try:
                    self.client = OpenAI(api_key=self.api_key)
                    self.log("OpenAI API connected successfully")
                except Exception as e:
                    self.log(f"Failed to initialize OpenAI client: {str(e)}", error=True)
                    self.use_openai = False
            else:
                if not OPENAI_AVAILABLE:
                    self.log("OpenAI module not available", warning=True)
                if not self.api_key:
                    self.log("OpenAI API key not provided", warning=True)
                self.use_openai = False
        
        # Fall back to local model if OpenAI not available/configured
        if not self.use_openai and LOCAL_AI_AVAILABLE:
            try:
                # Use a smaller local model suitable for security context
                model_path = "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF"
                self.log(f"Loading local AI model: {model_path}")
                
                self.local_tokenizer = AutoTokenizer.from_pretrained(model_path)
                self.local_model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    device_map="auto",
                    torch_dtype=torch.float16
                )
                self.model_name = "TinyLlama-1.1B (Local)"
                self.log("Local AI model loaded successfully")
            except Exception as e:
                self.log(f"Failed to load local AI model: {str(e)}", error=True)
                self.local_model = None
                self.local_tokenizer = None
    
    def ask(self, question: str) -> str:
        """Ask a question to the AI assistant
        
        This method will send the question to either OpenAI API or local model,
        and return the response
        
        Args:
            question: The question to ask
            
        Returns:
            AI assistant's response as string
        """
        if not question.strip():
            return "Please enter a question to get assistance."
        
        # Add user question to conversation history
        self.conversation_history.append({"role": "user", "content": question})
        
        # Prune conversation history if too long
        self._prune_conversation_history()
        
        # Generate response based on current AI backend
        response = ""
        if self.use_openai and self.client:
            response = self._generate_openai_response()
        elif self.local_model and self.local_tokenizer:
            response = self._generate_local_response()
        else:
            response = "AI assistant is not properly configured. Please provide an OpenAI API key or ensure local models are available."
        
        # Add assistant response to conversation history
        self.conversation_history.append({"role": "assistant", "content": response})
        
        return response
    
    def _generate_openai_response(self) -> str:
        """Generate a response using OpenAI API"""
        try:
            # Create messages including system message and conversation history
            messages = [{"role": "system", "content": self.system_message}]
            messages.extend(self.conversation_history)
            
            # Send request to OpenAI
            # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            # do not change this unless explicitly requested by the user
            completion = self.client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=0.7,
                max_tokens=1000
            )
            
            # Extract response
            response = completion.choices[0].message.content
            return response
        except Exception as e:
            error_message = f"Error generating response from OpenAI: {str(e)}"
            self.log(error_message, error=True)
            return f"I encountered an issue while processing your request: {str(e)}"
    
    def _generate_local_response(self) -> str:
        """Generate a response using local AI model"""
        try:
            # Format input for local model
            prompt = f"System: {self.system_message}\n\n"
            
            # Add conversation history
            for message in self.conversation_history:
                role = message["role"]
                content = message["content"]
                if role == "user":
                    prompt += f"User: {content}\n\n"
                elif role == "assistant":
                    prompt += f"Assistant: {content}\n\n"
            
            # Add final prompt for response
            prompt += "Assistant: "
            
            # Generate response with local model
            inputs = self.local_tokenizer(prompt, return_tensors="pt").to(self.local_model.device)
            with torch.no_grad():
                output = self.local_model.generate(
                    inputs["input_ids"],
                    max_new_tokens=500,
                    temperature=0.7,
                    top_p=0.9,
                    do_sample=True
                )
            
            # Decode response
            response = self.local_tokenizer.decode(output[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
            return response
        except Exception as e:
            error_message = f"Error generating response from local model: {str(e)}"
            self.log(error_message, error=True)
            return f"I encountered an issue while processing your request locally: {str(e)}"
    
    def _prune_conversation_history(self):
        """Prune conversation history to stay within token limits"""
        # Start with system message for token count
        total_tokens = len(self.system_message.split())
        
        # Count tokens in conversation history (rough estimation)
        for message in self.conversation_history:
            total_tokens += len(message["content"].split())
        
        # If over limit, remove oldest messages (but keep latest user question)
        while total_tokens > self.max_context_length and len(self.conversation_history) > 1:
            # Don't remove the latest message (which is the user question)
            removed_message = self.conversation_history.pop(0)
            total_tokens -= len(removed_message["content"].split())
    
    def diagnose_error(self, error_traceback: str) -> str:
        """Diagnose an error and suggest fixes
        
        Args:
            error_traceback: The traceback of the error
            
        Returns:
            AI diagnosis and suggested fixes
        """
        prompt = f"""
        I'm working with a WiFi Penetration Testing Tool and encountered the following error:
        
        ```
        {error_traceback}
        ```
        
        Please:
        1. Identify the root cause of this error
        2. Explain what's happening in clear terms
        3. Suggest specific steps to fix the issue
        4. If relevant, explain how to prevent similar errors in the future
        
        Focus on practical solutions that would work in a penetration testing context.
        """
        
        # Add error diagnosis prompt to conversation history
        self.conversation_history.append({"role": "user", "content": prompt})
        
        # Generate response
        response = ""
        if self.use_openai and self.client:
            response = self._generate_openai_response()
        elif self.local_model and self.local_tokenizer:
            response = self._generate_local_response()
        else:
            response = "Error diagnosis requires an AI backend. Please provide an OpenAI API key or ensure local models are available."
        
        # Add response to conversation history
        self.conversation_history.append({"role": "assistant", "content": response})
        
        return response
    
    def log(self, message: str, error=False, warning=False):
        """Log a message using the callback if available"""
        if self.log_callback:
            self.log_callback(message, error=error, warning=warning)
        else:
            # Fallback to print
            if error:
                print(f"[ERROR] {message}")
            elif warning:
                print(f"[WARNING] {message}")
            else:
                print(f"[INFO] {message}")
    
    def is_available(self) -> bool:
        """Check if any AI backend is available
        
        Returns:
            True if either OpenAI or local model is available
        """
        return (self.use_openai and self.client is not None) or (self.local_model is not None)
    
    def get_model_name(self) -> str:
        """Get the name of the active AI model
        
        Returns:
            Model name as string
        """
        return self.model_name

# Example usage when run directly
if __name__ == "__main__":
    # Test with dummy log function
    def test_log(message, error=False, warning=False):
        prefix = "[ERROR]" if error else "[WARNING]" if warning else "[INFO]"
        print(f"{prefix} {message}")
    
    # Test OpenAI (will fallback to local if no API key)
    api_key = os.environ.get("OPENAI_API_KEY")
    assistant = AIAssistant(use_openai=True, api_key=api_key, log_callback=test_log)
    
    # Ask a question to test
    print("\nTesting AI Assistant with a question:")
    question = "How do I capture a WPA2 handshake using this tool?"
    print(f"\nUser: {question}")
    response = assistant.ask(question)
    print(f"\nAssistant: {response}")
    
    # Test error diagnosis
    print("\nTesting Error Diagnosis:")
    error_traceback = """
    Traceback (most recent call last):
      File "/app/src/wifi_scanner.py", line 158, in scan_networks
        result = subprocess.check_output(['airmon-ng', 'start', interface])
      File "/usr/lib/python3.10/subprocess.py", line 420, in check_output
        return run(*popenargs, stdout=PIPE, timeout=timeout, check=True,
      File "/usr/lib/python3.10/subprocess.py", line 524, in run
        raise CalledProcessError(retcode, process.args,
    subprocess.CalledProcessError: Command '['airmon-ng', 'start', 'wlan0']' returned non-zero exit status 1.
    """
    diagnosis = assistant.diagnose_error(error_traceback)
    print(f"\nDiagnosis: {diagnosis}")