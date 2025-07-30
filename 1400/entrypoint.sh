#!/bin/sh

# Generate SSH host keys if they don't exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi

# Copy the provided authorized_keys into place
if [ -f /tmp/authorized_keys ]; then
    cp /tmp/authorized_keys /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    chmod 700 /root/.ssh 
    chown -R root:root /root/.ssh
fi

# Start SSH daemon in background
/usr/sbin/sshd -D &

# Start the quiznotes service with socat as app1 user
su -s /bin/sh app1 -c "cd /service/server && socat -d TCP-LISTEN:8000,reuseaddr,fork EXEC:'timeout -k 5 30 python3 -u server.py'"
