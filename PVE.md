# PVE support

## WARNING

This is an early version of PVE support. It has only been lightly tested. Please use with caution.

### Agent Configuration

```hcl
NodeAttestor "tpm" {
	plugin_cmd = "/path/to/plugin_cmd"
	plugin_checksum = "sha256 of the plugin binary"
	plugin_data {
	    pve {
            enabled = true
        }
    }
}
```

### Server Configuration

```hcl
NodeAttestor "tpm" {
	plugin_cmd = "/path/to/plugin_cmd"
	plugin_checksum = "sha256 of the plugin binary"
    plugin_data {
        ca_path = "/etc/spire/server/${SYSTEMD_INSTANCE}/tpm-direct/certs"
        hash_path = "/etc/spire/server/${SYSTEMD_INSTANCE}/tpm-direct/hashes"
        pve {
            enabled = true
            cluster "<Set cluster identifier here>" {
                hosts = [
                    "hypervisor1.exmaple.com",
                    "hypervisor2.exmaple.com",
                    "hypervisor3.exmaple.com"
                ]
                #port = 9443
                #expected_spiffe_id = "spiffe://example.com/spiffe-pve-ek"
                #hash_path = "/etc/spire/server/${SYSTEMD_INSTANCE}/tpm-direct/pve-hashes"
            }
        }
    }
}
```

Run one instance of the spiffe-pve-ek service on each hypervisor if running in a regular setup. Run one for spire-server-a and one for spire-server-b when in a spire-ha-agent setup.

Configure /etc/spiffe/pve-ek/default.env on each Proxmox hypervisor. Make up a cluster identifier for the cluster. run `uuidgen` and use that everywhere.

If your Proxmox setup has hypervosrs that do not use full hostnames, you can set DOMAIN= in the config to complete the node FQDNs.

Example:
```
SPIFFE_PVE_CLUSTER=951e201d-f804-4442-b922-699be0534f1b
#DOMAIN=pve.example.com
```

### Selectors

In addition to the regular:
Selectors         : tpm:pub_hash:xxx

You will also get selectors like this:
Selectors         : tpm:pve:cuid:951e201df8044442b922699be0534f1b
Selectors         : tpm:pve:name:test
Selectors         : tpm:pve:network:infra
Selectors         : tpm:pve:node:h72.example.com
Selectors         : tpm:pve:storage:Pool:vm-123-disk-1
Selectors         : tpm:pve:tag:dev
Selectors         : tpm:pve:uuid:fa34b48b-5657-41e0-8bbc-4866da9f2935
Selectors         : tpm:pve:vm_id:123

## Secuirty considerations of selectors

Some selectors are more secure then others. For instance, uuid is fairly unchanging. vm_id can be recycled by Proxmox as soon as that VM is deleted. Name is configurable by the person launching the VM. Use selectors wisely.
