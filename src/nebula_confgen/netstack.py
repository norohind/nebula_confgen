from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Literal, NotRequired, TypedDict


class FirewallRule(TypedDict):
    port: int | str
    proto: Literal['any', 'tcp', 'udp', 'icmp']
    ca_name: NotRequired[str]
    ca_sha: NotRequired[str]
    host: NotRequired[str]
    group: NotRequired[str]
    groups: NotRequired[list[str]]
    cidr: NotRequired[str]
    local_cidr: NotRequired[str]

@dataclass(frozen=True)
class AuthorizedUser:
    user: str
    keys: tuple[str, ...]


@dataclass(frozen=True)
class UnsafeRoute:
    route: str   # 172.16.1.0/24
    via: str     # 192.168.100.99
    mtu: int     # 1300
    metric: int  # 100
    install: bool = True

@dataclass(frozen=True)
class Host:
    name: str
    addr: str
    subnet: int = 24
    public_addresses: Iterable[str] = tuple()
    inbound_rules: tuple[FirewallRule, ...] = tuple()
    merge_stack_inbound_rules: bool = True
    config_prefix: str = "/etc/nebula"
    am_lighthouse: bool = False
    am_relay: bool = False
    serve_dns: bool = None
    tun_disabled: bool = False
    tun_name: str = 'nebula1'
    dns_host: str = "self.addr"
    dns_port: int = 53


class NetStack:
    def __init__(
            self,
            hosts: list[Host],
            ca: list[Path],
            listen_port: int = 4242,
            pki_blocklist: Iterable[str] = None,
            default_inbound_rules: tuple[FirewallRule, ...] = tuple(),
            authorized_users: tuple[AuthorizedUser, ...] = tuple(),
            enable_dns: bool = False
    ):
        self.hosts: list[Host] = list()

        self.listen_port = listen_port
        self.ca: list[str] = list()
        for ca_path in ca:
            self.ca.append(ca_path.read_text())

        if pki_blocklist is None:
            pki_blocklist = list()

        self.pki_blocklist = pki_blocklist
        self.add_hosts(hosts)

        self.default_inbound_rules = default_inbound_rules
        self.authorized_users = authorized_users

        self.enable_dns = enable_dns

    def add_host(self, host: Host) -> None:
        self.hosts.append(host)

    def add_hosts(self, hosts: Iterable[Host]) -> None:
        for host in hosts:
            self.add_host(host)

    def get_static_host_map_for(self, hostname: str) -> dict[str, list[str]]:
        res = dict()
        for host in self.hosts:
            if host.am_lighthouse is True and host.name != hostname:
                res[host.addr] = [f'{addr}:{self.listen_port}' for addr in host.public_addresses]

        return res

    def get_lighthouses_for(self, hostname: str) -> list[str]:
        return [host.addr for host in self.hosts if host.am_lighthouse and host.name != hostname]

    def get_config(self, host: Host) -> dict:
        if self.enable_dns:
            serve_dns = host.serve_dns if host.serve_dns is not None else host.am_lighthouse

        else:
            serve_dns = False

        inbound_rules: list[FirewallRule] = list(host.inbound_rules)
        if host.merge_stack_inbound_rules:
            inbound_rules.extend(self.default_inbound_rules)

        if serve_dns:
            inbound_rules.append({'port': 53, 'proto': 'any', 'group': 'any'})

        advertise_addrs: list[str] = []
        for addr in host.public_addresses:
            if ':' not in addr:
                addr = addr + ':0'

            advertise_addrs.append(addr)

        return {
            'pki': {
                'ca': '\n'.join(ca for ca in self.ca),  # We do support more than 1 ca for ca rotation
                'cert': f'{host.config_prefix}/{host.name}.crt',
                'key': f'{host.config_prefix}/{host.name}.key',
                'blocklist': self.pki_blocklist,
                'disconnect_invalid': True,
            },
            'static_host_map': self.get_static_host_map_for(host.name),
            'lighthouse': {
                'am_lighthouse': host.am_lighthouse,
                'serve_dns': serve_dns,
                'dns': {
                    'host': host.addr if host.dns_host == 'self.addr' else host.dns_host,
                    'port': host.dns_port
                },
                'hosts': sorted(self.get_lighthouses_for(host.name)),
                'local_allow_list': {'0.0.0.0/0': False},
                'advertise_addrs': advertise_addrs
            },
            'listen': {
                'port': self.listen_port
            },
            'punchy': {
                'respond': True
            },
            'preferred_ranges': ['192.168.1.0/24'],
            'relay': {
                'relays': sorted([other_host.addr for other_host in self.hosts if not host.am_relay and other_host.am_relay]),  # No relays if the host is relay
                'am_relay': host.am_relay,
            },
            'tun': {
                'disabled': host.tun_disabled,
                'dev': host.tun_name,
                'unsafe_routes': []  # TODO: UnsafeRoute
            },
            'sshd': {
                'enabled': True,
                'listen': host.addr + ':2222',
                'host_key': f'{host.config_prefix}/ssh_host_ed25519_key',
                'authorized_users': [{'user': i.user, 'keys': list(i.keys)} for i in self.authorized_users]
            },
            'firewall': {
                'outbound_action': 'drop',
                'inbound_action': 'drop',
                'conntrack': {
                    'tcp_timeout': '12m',
                    'udp_timeout': '3m',
                    'default_timeout': '10m',
                },
                'outbound': [{
                    'port': 'any',
                    'proto': 'any',
                    'host': 'any'
                }],
                'inbound': inbound_rules
            }
        }
