#!/bin/bash

echo "🔒 Securing firewall files..."

# Create integrity hash
python3 -c "
import hashlib
with open('firewall.py', 'rb') as f:
    hash_val = hashlib.sha256(f.read()).hexdigest()
with open('firewall.py.sha256', 'w') as f:
    f.write(hash_val)
print('Created integrity hash for firewall.py')
"

# Set secure permissions
sudo chown root:root firewall.py monitor_firewall.py firewall.py.sha256
sudo chmod 644 firewall.py firewall.py.sha256
sudo chmod 755 monitor_firewall.py

echo "✅ Files secured:"
echo "  - firewall.py: read-only, root owned"
echo "  - monitor_firewall.py: executable, root owned"
echo "  - firewall.py.sha256: integrity hash created"
echo ""
echo "⚠️  Only root can now modify firewall.py"
echo "💡 Run monitor as root: sudo python3 monitor_firewall.py"
