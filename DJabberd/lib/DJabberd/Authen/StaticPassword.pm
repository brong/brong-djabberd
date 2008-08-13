package DJabberd::Authen::StaticPassword;
use strict;
use base 'DJabberd::Authen';

sub set_config_password {
    my ($self, $pass) = @_;
    $self->{password} = $pass;
}

# If can_retrieve_cleartext is set to true,
# Authen.pm will register the GetPassword hook.
# That hook is then called from IQ.pm when a password
# needs to be checked. 
#
# The hook then invokes the get_password routine below, 
# which will return the static password and return it via
# the ->set method on the callback.
#
# IQ.pm will then validate that password and accept/reject
# it. This means no other hooks will get called in this chain.
# Also, none of the CheckCleartext/CheckDigest hooks will be 
# called.
#
# See the documentation in HookDocs about 'GetPassword' for 
# more details.
sub can_retrieve_cleartext { 1 }

# will be called if can_retrieve_cleartext returns 1
sub get_password {
    my ($self, $cb, %args) = @_;
    $cb->set($self->{password});
}

# will be called if can_retrieve_cleartext returns 0
sub check_cleartext {
    my ($self, $cb, %args) = @_;
    if ($args{password} eq $self->{password}) {
        $cb->accept;
        return;
    }
    $cb->reject;
}

1;
