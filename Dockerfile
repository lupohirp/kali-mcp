# Start with Kali Linux as the base
FROM kalilinux/kali-rolling:latest

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install Python and essential tools
RUN apt-get update && \
    apt-get install -y \
    python3-minimal \
    python3-pip \
    python3-venv \
    kali-linux-headless \
    sudo \
    libcap2-bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed -r requirements.txt

# Copy the MCP server
COPY server.py .
RUN chmod +x server.py

# Create non-root user with proper groups for network tools
RUN useradd -m -u 1000 -s /bin/bash mcpuser && \
    usermod -aG sudo mcpuser && \
    echo "mcpuser ALL=(ALL) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers && \
    chown -R mcpuser:mcpuser /app

# Set capabilities for network tools
RUN setcap cap_net_raw,cap_net_bind_service+eip /usr/lib/nmap/nmap

# Switch to non-root user (optional - you can stay as root if needed)
# USER mcpuser

# Set the entrypoint to run the MCP server
ENTRYPOINT ["python3", "/app/server.py"]