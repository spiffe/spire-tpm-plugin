#!/usr/bin/perl
use strict;
use warnings;

use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::Storage;
use PVE::Tools qw(run_command);
use File::Path qw(make_path);
use Socket qw(SOCK_STREAM);

my $vmid = shift;
my $phase = shift;

if ($phase eq 'pre-start') {
    print "TPM-ATTESTOR: Starting extraction for VM $vmid\n";

    my $source_node = $ENV{PVE_MIGRATED_FROM};
    my $tmp_dir = "/var/lib/swtpm/$vmid";

    make_path($tmp_dir) if !-d $tmp_dir;

    if ($source_node) {
        print "TPM-ATTESTOR: Live migration detected from $source_node. Syncing metadata...\n";
        eval {
            run_command([
                'scp',
                '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=no',
                "${source_node}:$tmp_dir/ek.pem",
                "${source_node}:$tmp_dir/uuid",
                $tmp_dir
            ]);
        };
        if ($@) {
            warn "TPM-ATTESTOR: Failed to sync EK/UUID from source node $source_node: $@\n";
	    exit(1);
        } else {
            print "TPM-ATTESTOR: Successfully migrated TPM metadata via SCP.\n";
            exit(0);
        }
    }

    # Load environment variables from default.env if it exists
    my $env_file = '/etc/spiffe/pve-ek/default.env';
    if (-f $env_file) {
        if (open(my $fh, '<', $env_file)) {
            while (my $line = <$fh>) {
                chomp $line;
                next if $line =~ /^\s*#/ || $line !~ /=/; # Skip comments or lines without '='
                my ($key, $val) = split('=', $line, 2);
                $key =~ s/^\s+|\s+$//g;
                $val =~ s/^\s+|\s+$//g;
                $ENV{$key} = $val;
            }
            close $fh;
        }
    }

    my $conf = PVE::QemuConfig->load_config($vmid);
    my $storecfg = PVE::Storage::config();

    my $tpm_key = $conf->{tpmstate0} ? 'tpmstate0' : ($conf->{tpm0} ? 'tpm0' : undef);

    my $smbios1 = $conf->{smbios1} || "";

    # 1. Parse existing values
    my $smbios_data = PVE::QemuServer::parse_smbios1($smbios1) || {};

    my $uuid = $smbios_data->{uuid};
    my $sku = $smbios_data->{sku};

    my $needs_update = 0;

    if (!$uuid) {
        warn "VM $vmid: smbios1 is missing a UUID!\n";
    }

    if (!$sku || $sku ne $vmid) {
        print "VM $vmid: Updating SMBIOS sku from '" . ($sku // "none") . "' to '$vmid'\n";
        $smbios_data->{sku} = $vmid;
        $needs_update = 1;
    }

    if (defined($ENV{SPIFFE_PVE_CLUSTER})) {
        my $target_serial = $ENV{SPIFFE_PVE_CLUSTER};
        if (!defined($smbios_data->{serial}) || $smbios_data->{serial} ne $target_serial) {
            print "VM $vmid: Updating SMBIOS serial to '$target_serial'\n";
            $target_serial =~ s/-//g;
            $smbios_data->{serial} = $target_serial;
            $needs_update = 1;
        }
    }

    if ($needs_update) {
        $conf->{smbios1} = PVE::QemuServer::print_smbios1($smbios_data);

        PVE::QemuConfig->write_config($vmid, $conf);
        print "VM $vmid: SMBIOS configuration updated successfully.\n";
    }

    if (!$tpm_key) {
        print "TPM-ATTESTOR: No TPM device defined for VM $vmid. Skipping.\n";
        exit(0);
    }

    my ($tpm_volid) = $conf->{$tpm_key} =~ m/^([^,]+)/;
    my $state_file = "$tmp_dir/tpm2-0.0.scope";
    my $ek_path = "$tmp_dir/ek.der";
    my $uuid_path = "$tmp_dir/uuid";

    eval {

        open(my $fh, '>', $uuid_path);
        print $fh $uuid;
        close $fh;

        print "TPM-ATTESTOR: Mapping volume $tpm_volid\n";
        # map_volume handles the activation and returns the /dev/rbd path
        my $src_path = PVE::Storage::map_volume($storecfg, $tpm_volid);

        # Give the system a heartbeat to ensure the block device is ready
        if (!-e $src_path) {
            for (1..5) {
                last if -e $src_path;
                select(undef, undef, undef, 0.2);
            }
        }

        if (-b $src_path) {
            print "TPM-ATTESTOR: Detected block device ($src_path). Using dd.\n";
            run_command(['dd', "if=$src_path", "of=$state_file", 'bs=1M', 'status=none']);
        } elsif (-f $src_path || -d $src_path) {
            # Handle directory-based storage (local/NFS)
            my $final_src = -d $src_path ? "$src_path/tpm2-0.0.scope" : $src_path;
            print "TPM-ATTESTOR: Detected file/dir ($final_src). Using cp.\n";
            run_command(['cp', $final_src, $state_file]);
        } else {
            die "Unsupported TPM state path type: $src_path\n";
        }

        # Start temporary swtpm
        my $swtpm_cmd = [
            'swtpm', 'socket', '--tpm2',
            '--tpmstate', "backend-uri=file://$state_file",
            '--server', "type=unixio,path=$tmp_dir/tpm",
            '--ctrl', "type=unixio,path=$tmp_dir/tpm.ctrl",
            '--flags', 'startup-clear',
            '--daemon'
        ];
        run_command($swtpm_cmd);

        my $max_attempts = 10;
        my $socket_path = "$tmp_dir/tpm.ctrl";
        my $connected = 0;
        for (1..$max_attempts) {
            if (-S $socket_path) {
                # Try to actually connect to ensure the daemon is listening, not just the file existing
                my $sock = IO::Socket::UNIX->new(
                    Type => SOCK_STREAM,
                    Peer => $socket_path,
                );

                if ($sock) {
                    $sock->close();
                    $connected = 1;
                    last;
                }
            }
            sleep(0.1); # 100ms pause
        }

        $ENV{TPM2TOOLS_TCTI} = "swtpm:path=$tmp_dir/tpm";

        my $hierarchy = '0x4000000B';
        my $index = '0x01c00002';
        my $der_path = "$tmp_dir/ek.der";
        my $pem_path = "$tmp_dir/ek.pem";
        eval {
            run_command(['tpm2_nvread', '-C', 'o', $index, '-o', $der_path]);

            if (-e $der_path) {
                run_command(['openssl', 'x509', '-inform', 'der', '-in', $der_path, '-out', $pem_path]);
                print "TPM-ATTESTOR: Successfully converted EK to PEM at $pem_path\n";
                unlink($der_path);
            }
            print "TPM-ATTESTOR: Successfully extracted EK cert to $pem_path\n";
        };
        warn "TPM-ATTESTOR: Could not read EK Cert. Index 0x01c00002 may be empty.\n" if $@;

        if (-S "$tmp_dir/tpm.ctrl") {
            run_command(['swtpm_ioctl', '--unix', "$tmp_dir/tpm.ctrl", '-s']);
        }

        # Unmap the volume when done to avoid 'device in use' errors for the VM
        PVE::Storage::unmap_volume($storecfg, $tpm_volid);
    };

    if ($@) {
        if (-e $state_file) {
                unlink($state_file);
        }
        warn "TPM-ATTESTOR ERROR: $@\n";
        # Clean up mapping even on error
        eval { PVE::Storage::unmap_volume($storecfg, $tpm_volid); };
    }
}

exit(0);
