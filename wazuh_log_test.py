from typing import Dict, List, Optional
import os

class WazuhLogTest:
    """Class to represesnt a single Wazuh log test within a tests.json file."""

    def __init__(self, rule_id: int, rule_level: int, format: str, rule_description: str, log_file: str,
                 predecoder: Optional[Dict[str, str]] = None, decoder: Optional[Dict[str, str]] = None):
        """
        Constructor for the WazuhLogTest class.
        
        Args:
        ----
            rule_id (int): The rule ID for the log test.
            rule_description (str): The description of the rule for the log test.
            log (str): The one line log to use for the test.
        """
        if not rule_id or rule_id < 0 or not isinstance(rule_id, int):
            raise ValueError("Rule ID cannot be empty.")
        
        if not rule_description or not isinstance(rule_description, str):
            raise ValueError("Rule description cannot be empty.")
        
        if not log_file or not isinstance(log_file, str):
            raise ValueError("Log file cannot be empty.")
        
        if not os.path.exists(log_file):
            raise ValueError(f"Log file: {log_file} does not exist.")

        if not format or not isinstance(format, str):
            raise ValueError("Log format cannot be empty.")
        
        if not rule_level or not isinstance(rule_level, int):
            raise ValueError("Rule level cannot be empty.")

        # New fields with validation
        if decoder and not isinstance(decoder, dict):
            raise ValueError("Decoder must be a dictionary.")
        if predecoder and not isinstance(predecoder, dict):
            raise ValueError("Predecoder must be a dictionary.")

        self.rule_id = rule_id
        self.rule_level = rule_level
        self.rule_description = rule_description
        self.log_file = log_file
        self.format = format
        self.decoder = decoder
        self.predecoder = predecoder

    def get_log(self) -> str:
        """
        Returns the one line log for the test.
        
        Returns:
        -------
            str: The one line log for the test.
        """
        with open(self.log_file, "r") as file:
            log = file.readline().strip("\n")

        return log
    
    def get_rule_level(self) -> int:
        """
        Returns the rule level for the test.
        
        Returns:
        -------
            int: The rule level for the test.
        """
        return self.rule_level
    
    def get_rule_id(self) -> int:
        """
        Returns the rule ID for the test.
        
        Returns:
        -------
            int: The rule ID for the test.
        """
        return self.rule_id
    
    def get_rule_description(self) -> str:
        """
        Returns the rule description for the test.
        
        Returns:
        -------
            str: The rule description for the test.
        """
        return self.rule_description
    
    def get_log_location(self) -> str:
        """
        Returns the location of the log for the test.
        
        Returns:
        -------
            str: The location of the log for the test.
        """
        return self.log_file
    
    def get_format(self) -> str:
        """
        Returns the log format for the test.
        
        Returns:
        -------
            str: The log format for the test.
        """
        return self.format

    def get_decoder(self) -> Optional[Dict[str, str]]:
        """
        Returns the decoder dictionary for the test, if present.

        Returns:
        -------
            Optional[Dict[str, str]]: The decoder dictionary or None if not present.
        """
        return self.decoder

    def get_predecoder(self) -> Optional[Dict[str, str]]:
        """
        Returns the predecoder dictionary for the test, if present.

        Returns:
        -------
            Optional[Dict[str, str]]: The predecoder dictionary or None if not present.
        """
        return self.predecoder
    