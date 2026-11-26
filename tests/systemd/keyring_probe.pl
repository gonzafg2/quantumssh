# Keyring probe for run_reference_unit.sh (ADR-0074 §4). The gate image
# has no keyctl(1), so this makes the system calls itself.
#
# Usage: perl keyring_probe.pl <add_key nr> <keyctl nr> add
#        perl keyring_probe.pl <add_key nr> <keyctl nr> search
#        perl keyring_probe.pl <add_key nr> <keyctl nr> read <serial>
#
#   add     links a `user` key "qssh-299" into @s, prints its serial, and
#           stays alive so the session's keyring does too;
#   search  searches @s for that key (KEYCTL_SEARCH);
#   read    asks for the key's length by serial (KEYCTL_READ, no buffer).
# search and read print "found <n>", "read <n>" or "errno <n>".
use strict;
use warnings;

my ($add_key, $keyctl, $op, $serial) = @ARGV;
my $session = -3;    # KEY_SPEC_SESSION_KEYRING
# syscall() may write through any string it passes, so none is a literal.
my ($type, $description, $payload) = ('user', 'qssh-299', 'secret');
$| = 1;
if ($op eq 'add') {
    my $key = syscall($add_key, $type, $description, $payload, length $payload, $session);
    die "add_key: $!\n" if $key < 0;
    print "$key\n";
    sleep 120;
} elsif ($op eq 'search') {
    my $r = syscall($keyctl, 10, $session, $type, $description, 0);
    print $r < 0 ? 'errno ' . ($! + 0) . "\n" : "found $r\n";
} elsif ($op eq 'read') {
    my $r = syscall($keyctl, 11, $serial + 0, 0, 0);
    print $r < 0 ? 'errno ' . ($! + 0) . "\n" : "read $r\n";
} else {
    die "unknown operation '$op'\n";
}
