#!/usr/bin/env python3
"""
Kali Linux MCP Server
Provides security testing tools through a containerized Kali Linux environment
"""

import subprocess
import logging
import os
import socket
from typing import Any

# Configure logging to stderr (required for MCP)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Import FastMCP AFTER logging setup
from fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP(
    name="kali-security-tools",
    instructions="""
    This MCP server provides access to Kali Linux security testing tools.
    All tools run directly in this container with proper isolation.
    
    Available tools include:
    - nmap: Network discovery and security auditing
    - nikto: Web server scanner
    - whatweb: Web technology fingerprinting
    - Custom commands: Execute any Kali Linux tool
    
    IMPORTANT: Only use these tools on systems you own or have explicit permission to test.
    """
)


def run_command(command: list[str], timeout: int = 300) -> dict[str, Any]:
    """Execute a command directly in this container"""
    try:
        logger.info(f"Executing command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/tmp"  # Use /tmp as working directory
        )
        
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        return {
            "success": False,
            "error": f"Command timed out after {timeout} seconds",
            "stdout": "",
            "stderr": ""
        }
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return {
            "success": False,
            "error": str(e),
            "stdout": "",
            "stderr": ""
        }


def check_privileges() -> dict:
    """Check if we're running with necessary privileges"""
    is_root = os.geteuid() == 0
    return {
        "is_root": is_root,
        "uid": os.geteuid(),
        "gid": os.getegid()
    }


@mcp.tool()
def check_container_permissions() -> str:
    """
    Check if the container is running with necessary privileges for security tools.
    
    Returns:
        Privilege information
    """
    
    privs = check_privileges()
    
    output = "🔍 Container Privilege Check:\n\n"
    output += f"Running as root: {'✅ YES' if privs['is_root'] else '❌ NO'}\n"
    output += f"User ID (UID): {privs['uid']}\n"
    output += f"Group ID (GID): {privs['gid']}\n\n"
    
    if not privs['is_root']:
        output += "⚠️ WARNING: Not running as root. Some tools may not work properly.\n"
        output += "Network scanning tools like nmap require root privileges.\n"
    else:
        output += "✅ Container has root privileges - all tools should work correctly.\n"
    
    # Also check if nmap is available
    result = run_command(["which", "nmap"], timeout=5)
    if result["success"]:
        output += f"\n📍 Nmap location: {result['stdout'].strip()}\n"
    
    # Check network capabilities
    result = run_command(["ip", "addr"], timeout=5)
    if result["success"]:
        output += f"\n🌐 Network interfaces available\n"
    
    return output


@mcp.tool()
def nmap_scan(
    target: str,
    scan_type: str = "basic",
    ports: str = ""
) -> str:
    """
    Perform network scanning with nmap.
    
    Args:
        target: Target IP address or hostname (e.g., '192.168.1.1' or 'example.com')
        scan_type: Type of scan - 'basic', 'quick', 'full', 'version', 'os'
        ports: Specific ports to scan (e.g., '22,80,443' or '1-1000'). Leave empty for default.
    
    Returns:
        Scan results from nmap
    
    IMPORTANT: Only scan systems you own or have permission to test!
    """
    
    # Check if we're root
    if os.geteuid() != 0:
        return "❌ Error: nmap requires root privileges. Container must run as root user."
    
    # Build nmap command based on scan type
    scan_commands = {
        "basic": ["nmap", "-Pn", target],  # Skip ping, basic scan
        "quick": ["nmap", "-Pn", "-T4", "-F", target],  # Fast scan
        "full": ["nmap", "-Pn", "-p-", target],  # All ports
        "version": ["nmap", "-Pn", "-sV", target],  # Service version detection
        "os": ["nmap", "-Pn", "-O", target]  # OS detection
    }
    
    command = scan_commands.get(scan_type, ["nmap", "-Pn", target])
    
    # Add custom ports if specified
    if ports:
        command = ["nmap", "-Pn", "-p", ports, target]
    
    result = run_command(command, timeout=600)
    
    if result["success"]:
        output = f"✅ Nmap scan completed successfully!\n\n{result['stdout']}"
        if result['stderr']:
            output += f"\n\nWarnings/Notes:\n{result['stderr']}"
        return output
    else:
        error_msg = result.get('error') or result.get('stderr', 'Unknown error')
        return f"❌ Nmap scan failed:\n{error_msg}\n\nStdout:\n{result.get('stdout', 'No output')}"


@mcp.tool()
def nikto_scan(target: str, port: int = 80, ssl: bool = False) -> str:
    """
    Scan web server with Nikto vulnerability scanner.
    
    Args:
        target: Target hostname or IP address
        port: Port number (default: 80)
        ssl: Use SSL/TLS (default: False)
    
    Returns:
        Nikto scan results
    
    IMPORTANT: Only scan web servers you own or have permission to test!
    """
    
    command = ["nikto", "-h", target, "-p", str(port)]
    if ssl:
        command.append("-ssl")
    
    result = run_command(command, timeout=900)
    
    if result["success"]:
        return f"✅ Nikto scan completed:\n\n{result['stdout']}"
    else:
        error_msg = result.get('error') or result.get('stderr', 'Unknown error')
        return f"❌ Nikto scan failed:\n{error_msg}"


@mcp.tool()
def whatweb_scan(target: str, aggression: int = 1) -> str:
    """
    Identify web technologies with WhatWeb.
    
    Args:
        target: Target URL (e.g., 'http://example.com')
        aggression: Scan aggression level 1-4 (default: 1, passive)
    
    Returns:
        Web technology fingerprinting results
    """
    
    command = ["whatweb", f"--aggression={aggression}", target]
    result = run_command(command, timeout=300)
    
    if result["success"]:
        return f"✅ WhatWeb scan completed:\n\n{result['stdout']}"
    else:
        error_msg = result.get('error') or result.get('stderr', 'Unknown error')
        return f"❌ WhatWeb scan failed:\n{error_msg}"


@mcp.tool()
def simple_port_scan(target: str, ports: str = "80,443,8080,22,21,25,3306") -> str:
    """
    Simple TCP port scanner that doesn't require special privileges.
    
    Args:
        target: Target IP address or hostname
        ports: Comma-separated list of ports (default: common ports)
    
    Returns:
        List of open ports
    """
    
    open_ports = []
    closed_ports = []
    
    port_list = [int(p.strip()) for p in ports.split(',')]
    
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)
        except Exception as e:
            closed_ports.append(port)
    
    output = f"✅ Port scan completed for {target}\n\n"
    output += f"Open ports ({len(open_ports)}):\n"
    output += ", ".join(str(p) for p in open_ports) if open_ports else "None found"
    output += f"\n\nClosed/filtered ports ({len(closed_ports)}):\n"
    output += ", ".join(str(p) for p in closed_ports)
    
    return output


@mcp.tool()
def run_custom_command(command: str, timeout: int = 300) -> str:
    """
    Run a custom command in the Kali Linux container.
    
    Args:
        command: Shell command to execute (e.g., 'ls -la /tmp')
        timeout: Command timeout in seconds (default: 300)
    
    Returns:
        Command output
    
    WARNING: Be careful with this tool - it executes arbitrary commands!
    """
    
    result = run_command(["bash", "-c", command], timeout=timeout)
    
    if result["success"]:
        output = f"✅ Command executed successfully:\n\n{result['stdout']}"
        if result['stderr']:
            output += f"\n\nStderr:\n{result['stderr']}"
        return output
    else:
        error_msg = result.get('error') or result.get('stderr', 'Unknown error')
        return f"❌ Command failed:\n{error_msg}\n\nStdout:\n{result.get('stdout', 'No output')}"


@mcp.tool()
def hydra_attack(target: str, service: str, user: str = "", user_file: str = "", password: str = "", password_file: str = "", additional_args: str = "") -> str:
    """
    Perform an online password cracking attack with Hydra.
    
    Args:
        target: Target IP or hostname
        service: Service to attack (e.g., 'ssh', 'ftp', 'http-post-form')
        user: Single username to test
        user_file: File containing list of usernames
        password: Single password to test
        password_file: File containing list of passwords
        additional_args: Any additional arguments for Hydra
    """
    command = ["hydra"]
    if user: command.extend(["-l", user])
    elif user_file: command.extend(["-L", user_file])
    
    if password: command.extend(["-p", password])
    elif password_file: command.extend(["-P", password_file])
        
    if additional_args: command.extend(additional_args.split())
        
    command.extend([target, service])
    
    result = run_command(command, timeout=900)
    if result["success"]:
        return f"✅ Hydra attack completed:\n\n{result['stdout']}"
    else:
        error_msg = result.get('error') or result.get('stderr', 'Unknown error')
        return f"❌ Hydra attack failed:\n{error_msg}\n\nStdout:\n{result.get('stdout', 'No output')}"


@mcp.tool()
def dirb_scan(target: str, wordlist: str = "", additional_args: str = "") -> str:
    """
    Scan web server for directories using Dirb.
    
    Args:
        target: Target URL
        wordlist: Optional path to custom wordlist
        additional_args: Optional extra arguments
    """
    command = ["dirb", target]
    if wordlist: command.append(wordlist)
    if additional_args: command.extend(additional_args.split())
        
    result = run_command(command, timeout=900)
    if result["success"]:
        return f"✅ Dirb scan completed:\n\n{result['stdout']}"
    else:
        error_msg = result.get('error') or result.get('stderr', 'Unknown error')
        return f"❌ Dirb scan failed:\n{error_msg}\n\nStdout:\n{result.get('stdout', 'No output')}"


@mcp.tool()
def metasploit_run(module: str, options: dict[str, str] = None) -> str:
    """
    Run a Metasploit module via msfconsole.
    
    Args:
        module: The Metasploit module to use (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
        options: Dictionary of options to set (e.g., {'RHOSTS': '192.168.1.5'})
    """
    commands = [f"use {module}"]
    if options:
        for k, v in options.items():
            commands.append(f"set {k} {v}")
    commands.append("run")
    commands.append("exit")
    
    msf_command = "; ".join(commands)
    result = run_command(["msfconsole", "-q", "-x", msf_command], timeout=1200)
    
    if result["success"]:
        return f"✅ Metasploit run completed:\n\n{result['stdout']}"
    else:
        error_msg = result.get('error') or result.get('stderr', 'Unknown error')
        return f"❌ Metasploit run failed:\n{error_msg}\n\nStdout:\n{result.get('stdout', 'No output')}"


@mcp.tool()
def list_available_tools() -> str:
    """
    List security tools available in this Kali Linux container.
    
    Returns:
        List of installed Kali Linux tools
    """
    
    result = run_command(["dpkg", "-l"], timeout=30)
    
    if result["success"]:
        # Filter for kali packages
        lines = result['stdout'].split('\n')
        kali_tools = [line for line in lines if 'kali' in line.lower()]
        
        return f"✅ Found {len(kali_tools)} Kali packages installed:\n\n" + '\n'.join(kali_tools[:50])
    else:
        return "❌ Failed to list tools"


if __name__ == "__main__":
    logger.info("Starting Kali Linux MCP Server...")
    logger.info(f"Running as UID: {os.geteuid()}")
    logger.info("Security tools are ready for use")
    
    # Run the MCP server
    mcp.run(transport="stdio")