package DJabberd::Authen::AllowedUsers;
use strict;
use base 'DJabberd::Authen';
use Carp qw(croak);

our $logger = DJabberd::Log->get_logger();

sub set_config_policy {
    my ($self, $policy) = @_;
    $policy = lc $policy;
    croak("Policy must be 'deny' or 'accept'") unless $policy =~ /^deny|accept$/;
    $self->{policy} = $policy;
}

sub set_config_allowedusers {
    my ($self, $val) = @_;
    $self->{allowed} = ref $val ? $val : [ split(/\s+/, $val) ];
}

sub set_config_deniedusers {
    my ($self, $val) = @_;
    $self->{denied} = ref $val ? $val : [ split(/\s+/, $val) ];
}

sub finalize {
    my $self = shift;
    # just for error checking:
    $self->set_config_policy($self->{policy});
    $self->{allowed} ||= [];
    $self->{denied}  ||= [];
}


# check_cleartext/digest and get_password do almost identical things here.
# one is the GetPassword hook, the other is the CheckCleartext/CheckDigest hook.
# The difference is in the callback usage:
#
# Hook              Accept          Decline         Reject
# GetPasswd:        $cb->set($pw)   $cb->decline    $cb->set('')
# CheckCleartext:   $cb->accept     $cb->decline    $cb->reject
# CheckDigest       $cb->accept     $cb->decline    $cb->reject
#
# Since this an exclusive plugin (deny users that aren't supposed to
# log in), we will never trigger the accept case. Instead, we decline
# and let another hook do the acceptance;
#
# To avoid code dupliation, we generate the 3 methods here;

# Enables the GetPassword hook, which will be registered in Authen.pm
sub can_retrieve_cleartext { 1 }

# Enabled the CheckDigest hook, which will be registered in Authen.pm
sub can_check_digest { 1 }

{   my %map = (
        # method name      # callback to reject
        get_password    => sub { my $cb = shift; $cb->set('') },
        check_cleartext => sub { my $cb = shift; $cb->reject  },
        check_digest    => sub { my $cb = shift; $cb->reject  },
    );
    
    while (my($name,$sub) = each %map) {

        no strict 'refs';
        *$name = sub {
            my ($self, $cb, %args) = @_;
            my $user = $args{'username'};
        
            if ($self->{'policy'} eq "deny") {
                $logger->debug("$self->$name --- user=$user, denying, unless allowed: @{$self->{allowed}}\n");
                foreach my $allowed (@{$self->{allowed}}) {
                    if (ref $allowed eq "Regexp" && $user =~ /$allowed/) {
                        $cb->decline; # okay username, may continue in auth phase
                        return;
                    } elsif ($user eq $allowed) {
                        $cb->decline; # okay username, may continue in auth phase
                        return;
                    }
                }
                $sub->($cb);
                return;
            }
        
            if ($self->{'policy'} eq "accept") {
                $logger->debug("$self->$name --- user=$user, accepting, unless denied: @{$self->{denied}}\n");
                foreach my $allowed (@{$self->{denied}}) {
                    if (ref $allowed eq "Regexp" && $user =~ /$allowed/) {
                        $sub->($cb); # okay username, may continue in auth phase
                        return;
                    } elsif ($user eq $allowed) {
                        $sub->($cb); # okay username, may continue in auth phase
                        return;
                    }
                }
                $cb->decline;
                return;
            }
        
            $sub->($cb);
        }
    }
}    
1;
