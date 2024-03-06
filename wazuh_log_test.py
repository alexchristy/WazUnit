from typing import Dict, List, Optional
import os

class WazuhLogTest:
    """Class to represesnt a single Wazuh log test within a tests.json file."""

    def __init__(self, rule_id: int, rule_level: int, format: str, rule_description: str, log_file: str, test_description: str,
                 predecoder: Optional[Dict[str, str]] = None, decoder: Optional[Dict[str, str]] = None):
        """
        Constructor for the WazuhLogTest class.
        
        Args:
        ----
            rule_id (int): The rule ID for the log test.
            rule_description (str): The description of the rule for the log test.
            log (str): The one line log to use for the test.
        """
        # Check if rule_id is empty or negative, and then check type
        if rule_id is None or rule_id < 0:
            raise ValueError("Rule ID must be provided and non-negative.")
        if not isinstance(rule_id, int):
            raise ValueError("Rule ID must be an integer.")

        # Check if rule_description is empty, and then check type
        if not rule_description:
            raise ValueError("Rule description cannot be empty.")
        if not isinstance(rule_description, str):
            raise ValueError("Rule description must be a string.")

        # Check if log_file is empty, and then check type
        if not log_file:
            raise ValueError("Log file cannot be empty.")
        if not isinstance(log_file, str):
            raise ValueError("Log file must be a string.")

        # Check if log file exists
        if not os.path.exists(log_file):
            raise ValueError(f"Log file: {log_file} does not exist.")

        # Check if format is empty, and then check type
        if not format:
            raise ValueError("Log format cannot be empty.")
        if not isinstance(format, str):
            raise ValueError("Log format must be a string.")

        # Check if rule_level is empty, and then check type
        if rule_level is None:
            raise ValueError("Rule level must be provided.")
        if not isinstance(rule_level, int):
            raise ValueError("Rule level must be an integer.")

        # Assuming 'test_description' exists and needs similar checks
        # Check if test_description is empty, and then check type
        if not test_description:
            raise ValueError("Test description cannot be empty.")
        if not isinstance(test_description, str):
            raise ValueError("Test description must be a string.")

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
        self.test_description = test_description

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
    
    def get_test_description(self) -> str:
        """
        Returns the test description for the test, if present.

        Returns:
        -------
            Optional[str]: The test description or None if not present.
        """
        return self.test_description
    