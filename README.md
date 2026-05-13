# Ghost-Ship

Infrastructure migration engine. Extracts full system state (databases, certs, Docker containers, Nomad jobs) from source server, provisions target identically, restores everything without downtime.

## Overview

Three phases:
1. **Extract** - Captures system state via SSH, encrypts with AES-256-GCM + LZ4 compression
2. **Provision** - Sets up target server (SSH hardening, firewall, Docker, Nomad)
3. **Restore** - Deploys all state to target (containers, jobs, volumes, configs)

Built with Go + C++ (OpenSSL, LZ4). Zero external Go dependencies besides SSH util.

## Architecture

### Components

**Phase 1: Soul Extractor**
- Databases: SQLite, SQLCipher from /opt/3x-ui, /var/lib, standard paths
- Certificates: TLS certs and keys from /etc/ssl, /root/.ssh
- Configs: Application configs, docker-compose.yaml, Nomad jobspecs
- SSH keys: public keys for access management
- TAR-based packaging with AES-256-GCM encryption + LZ4 compression
- Base64 encoding for safe SSH transmission

**Phase 2: Docker & Nomad Management**
- Docker: Full container inspection, named volume extraction, compose preservation
- Volume data: Extract as compressed tar from /var/lib/docker/volumes/
- Container restoration: Recreate with original ports, env vars, volumes
- Nomad: Job spec extraction with datacenter metadata, runtime validation
- Container runtime check: Ensures docker or containerd available on target

**Phase 3: Security Audit**
- System checks: SSH auth, UFW, Fail2Ban, SELinux/AppArmor, audit logging
- Docker checks: Daemon security options, resource limits, privileged containers, socket perms
- Nomad checks: TLS, ACL, audit logging
- Telegram integration for alerts (optional, via bot API)
- Severity levels: CRITICAL (immediate action), WARNING (needs attention), INFO

## Usage

### Setup
```bash
cd Ghost-Ship
go build -v ./cmd/gs
export SSH_KEY=/path/to/private/key
./gs
```

### Commands

**Land** - Provision fresh server
```bash
./gs land 192.168.1.100 configs/node.yaml
```
Installs and configures: Docker, Nomad, UFW, Fail2Ban, SSH hardening.

**Extract** - Capture state
```bash
./gs extract configs/node.yaml
```
Connects to source, extracts all state components, outputs compression stats.

**Migrate** - Full transfer (three phases)
```bash
./gs migrate --from 192.168.1.100 --to 192.168.1.101 --config configs/node.yaml
```
Phase 1: Extract from source
Phase 2: Provision target
Phase 3: Restore to target

**Audit** - Security check
```bash
./gs audit 192.168.1.100
```
Runs 12 security checks across system, docker, nomad. Outputs alerts with severity levels.

**Status** - Health check (reserved)
```bash
./gs status 192.168.1.100
```

## How Audit Works

Connects via SSH, runs bash commands on target, parses output to grade each check.

System security checks:
- grep PasswordAuthentication no from /etc/ssh/sshd_config
- ufw status | grep active
- systemctl is-active fail2ban
- getenforce or aa-status
- auditctl -l for sudo logging

Docker checks:
- docker info for security options
- docker inspect for resource limits and privileged containers
- ls -la /var/run/docker.sock permissions

Nomad checks:
- nomad operator raft list-peers
- nomad acl policy list
- nomad service registrations for audit

Each returns PASSED, WARNING (needs attention), or CRITICAL (fix required).

## Data Flow

Extraction:
```
Source SSH -> [Databases] TAR -> LZ4 compression -> AES-256-GCM -> Base64 -> Encrypted artifact
           -> [Certs] TAR |
           -> [Configs] TAR |
           -> [Docker] TAR |
           -> [Nomad] TAR
```

Restoration:
```
Encrypted artifact (SSH) -> Base64 decode -> AES-256-GCM decrypt -> LZ4 decompress -> TAR extract
                                                                                     -> /opt/3x-ui/db/*
                                                                                     -> /etc/ssl/*
                                                                                     -> /etc/x-ui/*
                                                                                     -> ~/.ssh/*
                                                                                     -> Docker volumes
                                                                                     -> Docker containers
                                                                                     -> Nomad jobs
```

## Implementation Notes

**Bash injection prevention**: Uses heredoc with single-quoted EOF delimiters
```bash
cat > /path/to/file << 'EOF'
content_here
EOF
```
Prevents shell variable interpolation in transferred configs.

**Volume handling**: Tar format preserves permissions
```bash
tar czf - -C /var/lib/docker/volumes/volumename . 2>/dev/null
tar xzf /tmp/volume.tar.gz -C /var/lib/docker/volumes/volumename
```

**Runtime validation**: Nomad requires container runtime (docker or containerd)
```go
hasDocker, _ := client.Run("docker --version")
hasContainerd, _ := client.Run("which containerd")
if hasDocker == "" && hasContainerd == "" {
    return fmt.Errorf("no container runtime found")
}
```

**Type safety**: SystemState uses concrete types, not map[string]interface{}
```go
type SystemState struct {
    Docker *nomad.DockerState
    Nomad  *nomad.NomadState
}
```
Avoids marshal/unmarshal overhead.

## Compression

Typical breakdown:
- Databases: 50-200 MB (already compressed by SQLite, minor savings)
- Certificates: 10-50 KB
- Configs (JSON): 1-10 MB (10x ratio with LZ4)
- Docker configs: 0.5-2 MB (10x ratio)
- Nomad jobspecs: 0.1-1 MB (10x ratio)

Full infrastructure state: 100 MB uncompressed becomes 20-30 MB encrypted.

## Limitations

- Assumes registry access on target for container images
- Volume restoration needs disk space for archive + extracted data
- Nomad jobs assume target datacenter names match source
- Audit checks assume standard service names (fail2ban, ufw, etc.)
- No automatic rollback (snapshot target before migration)

## Build

Prerequisites: Go 1.25+, GCC/Clang with C++20, CMake 3.10+, libssl-dev, liblz4-dev

```bash
make build        # Go binary
make build-c++    # C++ streamer library
```

Binary goes to ./gs

## Performance

Extraction: 50-100 MB/s (database reading), 5-10% CPU overhead
Restoration: Network-bound SSH, 100-200 MB/s TAR extraction
Typical migration: 5-15 minutes for full infrastructure

## Security

- SSH key-based auth only (SSH_KEY env var)
- AES-256-GCM encryption (authenticated, prevents tampering)
- All operations logged via slog
- No automatic key derivation (assumes high-entropy SSH key)

## License

See LICENSE file.