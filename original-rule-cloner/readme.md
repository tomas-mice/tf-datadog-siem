# Clone Datadog Original SIEM detection rules

As original, Datadog provided detection rules cannot be modified, we are clonning them as is with new prefix - [TBOL]

That gives us posibility to change configuraiton any of the rules. We clonning all, because it will be easier to maintain, as all embeded SIEM rules will be disabled and replaced with cloned ones

## How to use cloner.py

Make sure, that you have python3 installed or you can run it in docker
As well it is required to have valid Datadog API and APP keys in .env file

```bash

python3 -m venv .venv
source .venv/bin/activate
pip3 install requests
python3 cloner.py
deactivate

```

By default script will run in drymode, which wont actually clone anything. Run it in dry mode to see, what actually script will do.
Whenever ready, change `dry_run = False` and run it again
