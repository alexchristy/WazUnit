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
        <li><a href="#quickstart">Quickstart</a></li>
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

## Usage

This is the directory that will have all the tests and their associated log files.

### Tests Directory

This is the directory that will have all the tests and their associated log files. Tests can be grouped together by putting them together in the same directory. Each directory has to have a `tests.json` file which defines each of the tests and the paths to the txt files that have the raw log content.

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

*See the tests directory for a usable example.*

### tests.json

This file defines all the tests within a group. This is where you can define the correct output for each test. Below is a snippet of one of the example `tests.json` files included in the repo.

```json
{
    "tests": [
        {
            "test_desc": "Sniffing mode rule test.",
            "rule_id": "5104",
            "rule_level": "8",
            "format": "syslog",
            "description": "Interface entered in promiscuous(sniffing) mode.",
            "predecoder": {
                "hostname": "ip-10-0-0-12",
                "timestamp": "Mar  5 08:44:55"
            },
            "decoder": {
                "name": "kernel"
            },
            "log_file": "5104.txt"
        }
    ]
}
```

**Attributes:**

* `test_desc`: This field is here for you to describe the test. It will be used for log output when tests fail.
* `rule_id`: This defines the rule number the log should trigger as in Wazuh.
* `rule_level`: This is the level of the alert that should be generated from the log.
* `format`: This defines the format of the log. (Ex: `syslog`, `auditd`, etc.)
* `description`: This is the message that should created by the alert.
* `predecoder`: (OPTIONAL) This is a dictionary of key-value pairs to check the predecoder output for.
* `decoder`: (OPTIONAL) This is a dictionary of key-value pairs to check the decoder output for.
* `log_file`: This is the path to the file that has the raw log content to send to Wazuh. (Log must be on a single line)
