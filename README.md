<a name="readme-top"></a>

# Wazuh Rule Test

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#quickstart">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
  </ol>
</details>

## About the Project


![image](https://github.com/alexchristy/Wazuh-Unit-Test/assets/80216803/adc1e6b0-f37f-4813-901a-48f99a3adf79)


This is project is here to make it simple to modify your Wazuh decoders and rulesets with confidence. By leveraging the [Wazuh Logtest tool](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html) and [Wazuh API](https://documentation.wazuh.com/current/user-manual/api/getting-started.html), you can now automate and test your Wazuh rules easily.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Prerequisites

Make sure to clone the repository and install all dependencies.

1. Clone the repository

```bash
git clone https://github.com/alexchristy/Wazuh-Rule-Test.git
```
2. Create a virtual enviroment for dependencies.

```bash
cd Wazuh-Rule-Test
python3 -m venv venv
```
```bash
source ./venv/bin/activate
```

3. Install dependencies.

```bash
pip install -r requirements.txt
```

## Quickstart

The script it bundled with some demo tests in `tests/` that will work out of the box with the default Wazuh rules. If it is successful you will see an output similar to the screenshot in [About the Project](#About-the-Project)

```bash
python3 main.py -d ./tests/ -u {WAZUH_API_USERNAME} -p {PASSWORD} {WAZUH_MANAGER_IP_OR_HOSTNAME}
```

## Tests Directory

This is the directory that will have all the tests and their associated log files.

### Structure

Tests can be grouped together by putting them together in the same directory. Each directory has to have a `tests.json` file which defines each of the tests and the paths to the txt files that have the raw log content.

```
tests/
|
+----Group of Tests 1
|     |
|     +---tests.json
|     +---100001.txt
|    (...)
|
+----Group of Tests 2
      |
      +---tests.json
     (...)
```

### tests.json

This file defines all the tests within a group. This is where you can define the correct output for each test. Below is a snippet of one of the example `tests.json` files included in the repo.

```json
{
    "tests": [
        {
            "rule_id": "203",
            "rule_level": "9",
            "format": "wazuh",
            "description": "Agent event queue is full. Events may be lost.",
            "log_file": "203.txt" 
        }
    ]
}
```

**Attributes:**

* `rule_id`: This defines the rule number the log should trigger as in Wazuh.
* `rule_level`: This is the level of the alert that should be generated from the log.
* `format`: This defines the format of the log. (Ex: `syslog`, `auditd`, etc.)
* `description`: This is the message that should created by the alert.
* `log_file`: This is the path to the file that has the raw log content to send to Wazuh. (Log must be on a single line)
