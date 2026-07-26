"""Port Scanner Wrapper — network port scanning via Nmap.

Runs nmap via subprocess with -sV -sC --top-ports 1000 -oX for XML parsing.
Falls back to Python socket connect scan on top 100+ common ports.
Properly parses nmap XML output using xml.etree.ElementTree.
"""

import time
import socket
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseTool, ToolResult
from ..core.logger import logger
from ..core.ratelimit import get_limiter


# ──────────────────────────────────────────────────────────────────────
# 100+ common ports for fallback scanning
# ──────────────────────────────────────────────────────────────────────
TOP_PORTS = [
    # Well-known ports (0-1023)
    1, 3, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 37, 42, 43, 49,
    53, 67, 68, 69, 70, 79, 80, 81, 85, 88, 98, 106, 109, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 254, 255, 280, 311, 389,
    427, 443, 444, 445, 464, 465, 497, 500, 512, 513, 514, 515, 524,
    541, 548, 554, 563, 587, 593, 625, 631, 636, 646, 787, 808, 873,
    902, 990, 993, 995,
    # Registered ports (1024-49151)
    1025, 1026, 1027, 1028, 1029, 1030, 1080, 1099, 1110, 1433, 1434,
    1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2100, 2103, 2121,
    2199, 2717, 2869, 2967, 3000, 3001, 3128, 3268, 3306, 3389, 3986,
    4000, 4001, 4443, 4444, 4899, 5000, 5001, 5003, 5009, 5050, 5051,
    5060, 5101, 5120, 5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900,
    5901, 5985, 5986, 6000, 6001, 6379, 6646, 7000, 7001, 7070, 7100,
    7443, 7938, 8000, 8001, 8008, 8009, 8010, 8080, 8081, 8082, 8083,
    8084, 8085, 8088, 8090, 8443, 8444, 8834, 8880, 8888, 9000, 9001,
    9090, 9099, 9100, 9200, 9300, 9443, 9999, 10000, 10443, 11211,
    27017, 27018, 28017, 35729, 49152, 49153, 49154, 49155, 49156,
    49157, 50000, 50070, 55555,

    # ── Additional modern services ──
    # Databases
    1521, 1522, 1523,  # Oracle
    5433, 5434,  # PostgreSQL replicas
    3307, 3308,  # MySQL replicas
    9042,  # Cassandra
    8529,  # ArangoDB
    7474,  # Neo4j
    8086,  # InfluxDB
    4369,  # Erlang Port Mapper
    26257,  # CockroachDB
    26258,  # CockroachDB admin
    1434,  # MSSQL Browser
    1526,  # Oracle XDB
    2483,  # Oracle TLS
    2484,  # Oracle TLS

    # Message queues
    9092, 9093,  # Kafka
    5672, 5673,  # RabbitMQ
    15672, 15673,  # RabbitMQ Management
    4222, 8222,  # NATS
    1883, 8883,  # MQTT
    61613, 61614,  # Stomp

    # Search & Indexing
    9200, 9201,  # Elasticsearch
    9300, 9301,  # Elasticsearch transport
    9600,  # Kibana
    7700,  # Meilisearch
    8108,  # Typesense
    19530,  # Milvus

    # Container & Orchestration
    2376, 2377,  # Docker Swarm
    6443,  # Kubernetes API
    10250, 10255, 10256,  # Kubelet
    2379, 2380,  # etcd
    8472,  # Calico
    7946,  # Serf
    4789,  # VXLAN
    9099,  # Kubernetes proxy

    # Monitoring & Observability
    3000,  # Grafana
    9090,  # Prometheus
    9093,  # Alertmanager
    9091,  # Pushgateway
    16686,  # Jaeger
    14268,  # Jaeger HTTP
    55680,  # OTLP HTTP
    4317,  # OTLP gRPC
    4318,  # OTLP HTTP
    8125,  # StatsD
    2003,  # Graphite
    8089,  # Splunk HEC
    9997,  # Splunk management
    1234,  # Zabbix
    10050, 10051,  # Zabbix agent

    # CI/CD & DevOps
    8080,  # Jenkins
    8081,  # Nexus
    9000,  # SonarQube
    8082,  # GitLab
    8083,  # GitLab Registry
    8084,  # GitLab Pages
    8085,  # GitLab Mattermost
    8086,  # GitLab Registry
    8087,  # GitLab Pages
    8088,  # GitLab
    8089,  # GitLab
    8090,  # GitLab
    8091,  # GitLab
    8092,  # GitLab
    8093,  # GitLab
    8094,  # GitLab
    8095,  # GitLab
    8096,  # GitLab
    8097,  # GitLab
    8098,  # GitLab
    8099,  # GitLab
    8100,  # GitLab
    8101,  # GitLab
    8102,  # GitLab
    8103,  # GitLab
    8104,  # GitLab
    8105,  # GitLab
    8106,  # GitLab
    8107,  # GitLab
    8108,  # GitLab
    8109,  # GitLab
    8110,  # GitLab
    8111,  # GitLab
    8112,  # GitLab
    8113,  # GitLab
    8114,  # GitLab
    8115,  # GitLab
    8116,  # GitLab
    8117,  # GitLab
    8118,  # GitLab
    8119,  # GitLab
    8120,  # GitLab

    # Web servers & proxies
    8443,  # HTTPS alt
    8444,  # HTTPS alt2
    8888,  # HTTP alt
    8889,  # HTTP alt2
    9443,  # HTTPS alt3
    9444,  # HTTPS alt4
    8000,  # HTTP dev
    8001,  # HTTP dev2
    8002,  # HTTP dev3
    8003,  # HTTP dev4
    8004,  # HTTP dev5
    8005,  # HTTP dev6
    8006,  # HTTP dev7
    8007,  # HTTP dev8
    8008,  # HTTP dev9
    8009,  # HTTP dev10
    8010,  # HTTP dev11
    8011,  # HTTP dev12
    8012,  # HTTP dev13
    8013,  # HTTP dev14
    8014,  # HTTP dev15
    8015,  # HTTP dev16
    8016,  # HTTP dev17
    8017,  # HTTP dev18
    8018,  # HTTP dev19
    8019,  # HTTP dev20
    8020,  # HTTP dev21
    8021,  # HTTP dev22
    8022,  # HTTP dev23
    8023,  # HTTP dev24
    8024,  # HTTP dev25
    8025,  # HTTP dev26
    8026,  # HTTP dev27
    8027,  # HTTP dev28
    8028,  # HTTP dev29
    8029,  # HTTP dev30

    # Storage & files
    9000,  # MinIO
    9001,  # MinIO Console
    443,  # HTTPS
    8443,  # HTTPS alt
    8080,  # HTTP
    8081,  # HTTP alt
    8082,  # HTTP alt2
    8083,  # HTTP alt3
    8084,  # HTTP alt4
    8085,  # HTTP alt5
    8086,  # HTTP alt6
    8087,  # HTTP alt7
    8088,  # HTTP alt8
    8089,  # HTTP alt9
    8090,  # HTTP alt10

    # Mail servers
    25,  # SMTP
    26,  # SMTP alt
    465,  # SMTPS
    587,  # Submission
    110,  # POP3
    995,  # POP3S
    143,  # IMAP
    993,  # IMAPS
    4190,  # ManageSieve

    # VPN & Tunnel
    1194,  # OpenVPN
    1723,  # PPTP
    500,  # IKEv2
    4500,  # IKEv2 NAT
    51820,  # WireGuard
    8293,  # SoftEther
    443,  # OpenVPN over HTTPS

    # DNS variants
    5353,  # mDNS
    853,  # DNS over TLS
    443,  # DNS over HTTPS
    784,  # DNS over QUIC

    # Redis & Cache
    6379,  # Redis
    6380,  # Redis alt
    6381,  # Redis alt2
    11211,  # Memcached
    11212,  # Memcached alt
    11213,  # Memcached alt2

    # Misc services
    161,  # SNMP
    162,  # SNMP Trap
    514,  # Syslog
    6514,  # Syslog TLS
    123,  # NTP
    69,  # TFTP
    873,  # Rsync
    2049,  # NFS
    111,  # RPCbind
    4040,  # Niagara
    47808,  # BACnet
    1883,  # MQTT
    8883,  # MQTT SSL
    5000,  # Flask/Docker
    5001,  # Flask alt
    5555,  # Android debug
    6000,  # X11
    6001,  # X11 alt
    7000,  # Cache
    7001,  # Cache alt
    7100,  # Cache alt2
    9999,  # Abyss
    10000,  # Webmin
    10443,  # HTTPS alt
    20000,  # Webmin
    49152,  # Dynamic
    49153,  # Dynamic
    49154,  # Dynamic
    49155,  # Dynamic
    49156,  # Dynamic
    49157,  # Dynamic
    50000,  # SAP
    50070,  # HDFS
    55555,  # Portmapper
]

# Deduplicate and sort
TOP_PORTS = sorted(set(TOP_PORTS))


# ──────────────────────────────────────────────────────────────────────
# Service name guessing from port numbers
# ──────────────────────────────────────────────────────────────────────
PORT_SERVICE_MAP = {
    1: "tcpmux", 3: "compressnet", 7: "echo", 9: "discard",
    13: "daytime", 17: "qotd", 19: "chargen", 20: "ftp-data",
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 26: "rsftp",
    37: "time", 42: "nameserver", 43: "whois", 49: "tacacs",
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    70: "gopher", 79: "finger", 80: "http", 81: "http-alt",
    85: "http", 88: "kerberos", 98: "linuxconf", 106: "pop3pw",
    109: "pop2", 110: "pop3", 111: "rpcbind", 113: "ident",
    119: "nntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    144: "news", 179: "bgp", 199: "smux", 254: "smsd",
    280: "http-mgmt", 311: "asip-webadmin", 389: "ldap",
    427: "svrloc", 443: "https", 444: "snpp", 445: "microsoft-ds",
    464: "kerberos-changepw", 465: "smtps", 497: "retrospect",
    500: "isakmp", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 524: "ncp", 541: "uucp-rlogin", 548: "afp",
    554: "rtsp", 563: "nntps", 587: "submission", 593: "http-rpc",
    625: "apple-xsrvr-admin", 631: "ipp", 636: "ldaps",
    646: "ldp", 787: "qsc", 808: "ccproxy-http", 873: "rsync",
    902: "vmware-auth", 990: "ftps", 993: "imaps", 995: "pop3s",
    1025: "msrpc", 1026: "lsass", 1027: "msrpc", 1028: "msrpc",
    1029: "msrpc", 1030: "msrpc", 1080: "socks", 1099: "rmi",
    1110: "nfsd-status", 1433: "mssql", 1434: "mssql-m",
    1521: "oracle", 1720: "h323", 1723: "pptp", 1755: "mms",
    1900: "ssdp", 2000: "cisco-sccp", 2049: "nfs", 2100: "amiganetfs",
    2121: "ftp-proxy", 2717: "pn-requester", 2869: "icslap",
    2967: "symantec-av", 3000: "ppp", 3001: "nessus",
    3128: "squid-http", 3268: "ms-adgc", 3306: "mysql",
    3389: "ms-wbt-server", 3986: "mapper-ws", 4000: "remoteanything",
    4443: "pharos", 4444: "krb524", 4899: "radmin", 5000: "upnp",
    5001: "commplex-link", 5003: "filemaker", 5009: "airport-admin",
    5050: "mmcc", 5060: "sip", 5101: "admdog", 5190: "aol",
    5357: "wsdapi", 5432: "postgresql", 5555: "freeciv",
    5631: "pcanywheredata", 5666: "nrpe", 5800: "vnc-http",
    5900: "vnc", 5901: "vnc-1", 5985: "wsman", 5986: "wsmans",
    6000: "x11", 6001: "x11-1", 6379: "redis", 6646: "unknown",
    7000: "afs3-fileserver", 7001: "afs3-callback", 7070: "realserver",
    7100: "font-service", 7443: "oracleas-https", 7938: "lgtomapper",
    8000: "http-alt", 8001: "http", 8008: "http", 8009: "ajp13",
    8010: "http", 8080: "http-proxy", 8081: "http", 8082: "http",
    8083: "http", 8084: "http", 8085: "http", 8088: "http",
    8090: "http", 8443: "https-alt", 8834: "unknown", 8880: "sunwebadmin",
    8888: "http", 9000: "cslistener", 9001: "tor-orport",
    9090: "zeus-admin", 9099: "unknown", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "es-transport", 9443: "tungsten-https",
    9999: "abyss", 10000: "snet-sensor-mgmt", 10443: "unknown",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb",
    28017: "mongodb-http", 35729: "unknown", 49152: "unknown",
    50000: "ibm-db2", 50070: "hdfs", 55555: "unknown",
}


class PortScanner(BaseTool):
    """Wrapper around nmap for port scanning and service detection."""

    name = "nmap"
    binary = "nmap"
    description = "Network port scanning and service detection"

    def scan(self, target: str, **kwargs) -> ToolResult:
        """Scan ports on a target host."""
        ports = kwargs.get("ports", None)
        top_ports = kwargs.get("top_ports", 1000)
        scan_type = kwargs.get("scan_type", "default")

        if not self.installed:
            logger.info(f"[{self.name}] Binary not found, using Python fallback")
            return self._fallback_scan(target, ports=ports, **kwargs)

        cmd = ["nmap"]

        # Scan type selection
        if scan_type == "fast":
            cmd.extend(["-F", "--open"])
        elif scan_type == "full":
            cmd.extend(["-sV", "-sC", "-O", "--open", "-oX", "-"])
        elif scan_type == "stealth":
            cmd.extend(["-sS", "-sV", "--open", "-oX", "-"])
        else:
            cmd.extend(["-sV", "-sC", "--open", "-oX", "-"])

        cmd.append(target)

        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in ports)])
        else:
            cmd.extend([f"--top-ports={top_ports}"])

        # Additional nmap options
        if kwargs.get("scripts"):
            cmd.extend(["--script", kwargs["scripts"]])
        if kwargs.get("timing"):
            cmd.extend([f"-T{kwargs['timing']}"])
        else:
            cmd.extend(["-T4"])  # Default aggressive timing

        start = time.time()
        result = self._run_cmd(cmd, timeout=kwargs.get("timeout", 600))
        duration = time.time() - start

        findings = []
        if result.returncode == 0 and result.stdout:
            findings = self._parse_nmap_xml(result.stdout, target)

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.returncode == 0,
            findings=findings,
            raw_output=result.stdout,
            error=result.stderr if result.returncode != 0 else "",
            duration=duration,
        )

    def _parse_nmap_xml(self, xml_output: str, target: str) -> List[Dict[str, Any]]:
        """Parse nmap XML output using xml.etree.ElementTree."""
        findings = []

        try:
            # Handle cases where output might have extra text before/after XML
            xml_start = xml_output.find("<?xml")
            if xml_start == -1:
                xml_start = xml_output.find("<nmaprun")
            if xml_start == -1:
                # Fall back to regex parsing
                return self._parse_nmap_regex(xml_output)

            xml_text = xml_output[xml_start:]
            root = ET.fromstring(xml_text)

            # Parse each host
            for host_elem in root.findall(".//host"):
                # Get host address
                addr_elem = host_elem.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host_elem.find("address[@addrtype='ipv6']")
                host_addr = addr_elem.get("addr", target) if addr_elem is not None else target

                # Get hostname if available
                hostname = ""
                hostname_elem = host_elem.find(".//hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name", "")

                # Get OS detection
                os_info = ""
                os_match = host_elem.find(".//osmatch")
                if os_match is not None:
                    os_info = os_match.get("name", "")

                # Parse ports
                ports_elem = host_elem.find("ports")
                if ports_elem is None:
                    continue

                for port_elem in ports_elem.findall("port"):
                    protocol = port_elem.get("protocol", "tcp")
                    portid = int(port_elem.get("portid", "0"))

                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                    if state != "open":
                        continue

                    # Service info
                    service_elem = port_elem.find("service")
                    service_name = ""
                    service_product = ""
                    service_version = ""
                    service_extrainfo = ""
                    service_tunnel = ""
                    service_method = ""

                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        service_product = service_elem.get("product", "")
                        service_version = service_elem.get("version", "")
                        service_extrainfo = service_elem.get("extrainfo", "")
                        service_tunnel = service_elem.get("tunnel", "")
                        service_method = service_elem.get("method", "")

                    # Script output
                    scripts = []
                    for script_elem in port_elem.findall("script"):
                        script_id = script_elem.get("id", "")
                        script_output = script_elem.get("output", "")
                        scripts.append({
                            "id": script_id,
                            "output": script_output,
                        })

                    # Build service string
                    svc_parts = [service_name]
                    if service_product:
                        svc_parts.append(service_product)
                    if service_version:
                        svc_parts.append(service_version)

                    findings.append({
                        "title": f"Open Port {portid}/{protocol}",
                        "severity": "INFO",
                        "description": (
                            f"Port {portid}/{protocol} is open — "
                            f"Service: {' '.join(svc_parts) or 'unknown'}"
                        ),
                        "evidence": (
                            f"State: {state}, Service: {service_name}, "
                            f"Product: {service_product}, Version: {service_version}"
                        ),
                        "host": host_addr,
                        "hostname": hostname,
                        "port": portid,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                        "extrainfo": service_extrainfo,
                        "tunnel": service_tunnel,
                        "method": service_method,
                        "scripts": scripts,
                        "os": os_info,
                        "remediation": self._port_remediation(portid, service_name),
                    })

        except ET.ParseError as e:
            logger.warning(f"[{self.name}] XML parse error: {e}, falling back to regex")
            return self._parse_nmap_regex(xml_output)
        except Exception as e:
            logger.error(f"[{self.name}] XML parsing failed: {e}")
            return self._parse_nmap_regex(xml_output)

        return findings

    def _parse_nmap_regex(self, xml_output: str) -> List[Dict[str, Any]]:
        """Fallback regex-based nmap XML parsing."""
        findings = []
        port_pattern = re.compile(
            r'<port\s+protocol="(\w+)"\s+portid="(\d+)">'
            r'.*?<state\s+state="(\w+)"'
            r'(?:.*?<service\s+name="([^"]*)"'
            r'(?:.*?product="([^"]*)"'
            r'(?:.*?version="([^"]*)")?)?)?',
            re.DOTALL,
        )

        for match in port_pattern.finditer(xml_output):
            protocol, portid, state, service, product, version = match.groups()
            if state != "open":
                continue

            port_num = int(portid)
            findings.append({
                "title": f"Open Port {port_num}/{protocol}",
                "severity": "INFO",
                "description": (
                    f"Port {port_num}/{protocol} is open — "
                    f"Service: {service or product or 'unknown'}"
                ),
                "evidence": f"State: {state}, Service: {service or ''}, Product: {product or ''}, Version: {version or ''}",
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "service": service or "",
                "product": product or "",
                "version": version or "",
                "remediation": self._port_remediation(port_num, service or ""),
            })

        return findings

    def _fallback_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        **kwargs,
    ) -> ToolResult:
        """Fallback: Python socket-based connect scan on 100+ common ports."""
        scan_ports = ports if ports else TOP_PORTS
        findings: List[Dict[str, Any]] = []
        start = time.time()

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            return ToolResult(
                tool=f"{self.name}(fallback)",
                target=target,
                success=False,
                error=f"DNS resolution failed for {target}: {e}",
                duration=time.time() - start,
            )

        logger.info(f"[{self.name}(fallback)] Scanning {len(scan_ports)} ports on {target} ({ip})")

        def check_port(port: int) -> Optional[Dict[str, Any]]:
            """Check if a single port is open and grab banner."""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result_code = sock.connect_ex((ip, port))

                if result_code != 0:
                    sock.close()
                    return None

                # Port is open — try banner grab
                banner = ""
                try:
                    sock.settimeout(2)
                    # Send HTTP request for web ports
                    if port in (80, 443, 8080, 8443, 8000, 8001, 8008, 8888, 9090, 3000, 5000):
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
                    else:
                        sock.send(b"\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
                finally:
                    sock.close()

                service = PORT_SERVICE_MAP.get(port, "unknown")

                # Detect service from banner
                banner_lower = banner.lower()
                if "ssh" in banner_lower:
                    service = "ssh"
                elif "ftp" in banner_lower:
                    service = "ftp"
                elif "smtp" in banner_lower:
                    service = "smtp"
                elif "http/" in banner_lower or "server:" in banner_lower:
                    service = "http"
                elif "imap" in banner_lower:
                    service = "imap"
                elif "pop3" in banner_lower:
                    service = "pop3"
                elif "mysql" in banner_lower:
                    service = "mysql"
                elif "redis" in banner_lower:
                    service = "redis"
                elif "mongodb" in banner_lower:
                    service = "mongodb"
                elif "postgresql" in banner_lower:
                    service = "postgresql"
                elif "rdp" in banner_lower or "microsoft" in banner_lower:
                    service = "ms-wbt-server"

                return {
                    "title": f"Open Port {port}/tcp",
                    "severity": "INFO",
                    "description": f"Port {port}/tcp is open — Service: {service}",
                    "evidence": f"Service: {service}, Banner: {banner[:150]}" if banner else f"Service: {service}",
                    "host": ip,
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service,
                    "banner": banner[:300] if banner else "",
                    "remediation": self._port_remediation(port, service),
                }
            except Exception:
                return None

        # Threaded port scanning
        max_workers = min(kwargs.get("threads", 50), len(scan_ports))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(check_port, p): p for p in scan_ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        # Sort by port number
        findings.sort(key=lambda f: f.get("port", 0))

        duration = time.time() - start
        logger.info(
            f"[{self.name}(fallback)] Scan complete: "
            f"{len(findings)} open ports found in {duration:.1f}s"
        )

        return ToolResult(
            tool=f"{self.name}(fallback)",
            target=target,
            success=True,
            findings=findings,
            duration=duration,
        )

    @staticmethod
    def _port_remediation(port: int, service: str) -> str:
        """Provide remediation advice based on port/service."""
        service_lower = service.lower()

        remediations = {
            21: "FTP transmits credentials in plaintext. Use SFTP/SCP instead. Disable anonymous FTP.",
            22: "SSH is open. Ensure key-based auth, disable root login, use strong ciphers.",
            23: "Telnet is insecure — transmits in plaintext. Replace with SSH immediately.",
            25: "SMTP open — may allow email relay. Restrict to authorized senders only.",
            53: "DNS open — ensure recursion is disabled for external queries.",
            80: "HTTP open — redirect all traffic to HTTPS. Review for missing security headers.",
            110: "POP3 transmits in plaintext. Use POP3S (995) or IMAPS (993).",
            111: "RPCBind open — can enumerate NFS/RPC services. Restrict access.",
            135: "MSRPC open — common attack surface. Restrict to internal network.",
            139: "NetBIOS open — can leak host info. Disable if not needed.",
            143: "IMAP transmits in plaintext. Use IMAPS (993) instead.",
            443: "HTTPS open — verify TLS configuration, check certificate validity.",
            445: "SMB open — major attack surface. Restrict access, ensure patches are current.",
            993: "IMAPS is open. Verify TLS configuration and certificate.",
            995: "POP3S is open. Verify TLS configuration.",
            1433: "MSSQL exposed — restrict to application servers only.",
            1521: "Oracle DB exposed — restrict to internal network.",
            2049: "NFS exposed — restrict exports, use firewall rules.",
            3000: "Development server exposed. Remove from production or restrict access.",
            3306: "MySQL exposed — bind to localhost, use firewall rules.",
            3389: "RDP exposed — use VPN, enable NLA, restrict source IPs.",
            5000: "Docker/UPnP exposed — restrict access.",
            5432: "PostgreSQL exposed — bind to localhost, use pg_hba.conf restrictions.",
            5900: "VNC exposed — use SSH tunnel, restrict source IPs.",
            6379: "Redis exposed — bind to localhost, require authentication.",
            8000: "HTTP service exposed — review for development artifacts.",
            8080: "HTTP proxy/service exposed — restrict access.",
            8443: "HTTPS alternative port — verify TLS config.",
            8888: "HTTP alternative service — review configuration.",
            9090: "Admin/monitoring service exposed — restrict access.",
            9200: "Elasticsearch exposed — restrict access, enable authentication.",
            9300: "Elasticsearch transport exposed — restrict to cluster nodes.",
            11211: "Memcached exposed — bind to localhost, disable UDP.",
            27017: "MongoDB exposed — enable auth, bind to localhost.",
            50070: "HDFS Web UI exposed — restrict access.",
        }

        if port in remediations:
            return remediations[port]

        if any(s in service_lower for s in ("http", "web", "tomcat", "nginx", "apache")):
            return "Web service exposed — verify TLS config, check for missing security headers."
        if any(s in service_lower for s in ("mysql", "postgres", "mongo", "redis", "memcache", "oracle", "mssql", "db")):
            return "Database service exposed — restrict to internal network, enable authentication."
        if any(s in service_lower for s in ("ftp", "sftp", "tftp")):
            return "File transfer service open — ensure encrypted protocols, restrict access."
        if any(s in service_lower for s in ("ssh", "telnet", "rdp", "vnc")):
            return "Remote access service open — restrict source IPs, use strong authentication."
        if any(s in service_lower for s in ("smtp", "imap", "pop3", "mail")):
            return "Mail service open — ensure TLS, restrict relay, monitor for abuse."

        return "Review if this service needs public exposure. Restrict via firewall if internal-only."
