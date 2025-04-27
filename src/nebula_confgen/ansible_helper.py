import json
from dataclasses import dataclass
from pathlib import Path

from .netstack import Host, NetStack


@dataclass(frozen=True)
class AnsibleHost(Host):
    """Represents ansible host"""

    ansible_host: str = None
    nebula_groups: str | None = None
    inventory_include: bool = True
    nebula_service_name: str = None
    service_manager: str = None

    def __post_init__(self):
        assert self.ansible_host


def get_output_dir(output_dir: Path = None) -> Path:
    if output_dir is None:
        output_dir = Path(__file__).parent.parent

    return output_dir

def generate_config(stack: NetStack, output_dir: Path = None) -> None:
    import yaml

    output_dir = get_output_dir(output_dir)

    generated = output_dir / Path('configs')
    generated.mkdir(exist_ok=True)

    for host in stack.hosts:
        config = stack.get_config(host)
        (generated / (host.name + '.yaml')).write_text(yaml.dump(config))

def generate_inventory(stack: NetStack, output_dir: Path = None) -> None:
    # Produce inventory for use with ansible

    output_dir = get_output_dir(output_dir)

    inventory_hosts = dict()
    for host in stack.hosts:
        if isinstance(host, AnsibleHost) is False or getattr(host, 'inventory_include', False) is False:
            print(f"Skipping host {host.name!r} for ansible inventory")
            continue

        host_vars = {
            'ansible_host': host.ansible_host,
            'nebula_addr': f'{host.addr}/{host.subnet}'
        }

        for var_name in ('nebula_groups', 'nebula_service_name', 'service_manager'):
            if getattr(host, var_name):
                host_vars[var_name] = getattr(host, var_name)

        inventory_hosts[host.name] = host_vars

    inventory = {'linux': {'hosts': inventory_hosts}}

    with open(output_dir / 'inventory.json', 'w', encoding='utf-8') as f:
        json.dump(inventory, f, indent=2, ensure_ascii=False)
