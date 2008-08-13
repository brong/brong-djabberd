package DJabberd::Plugin::CheckUsername;
use strict;
use warnings;

use base 'DJabberd::Plugin';

sub register {
    my ($self, $vhost) = @_;

    # XXX FIXME this is compatible with the current implementation
    # but should use nodeprep ideally. The etails are here:
    #  http://www.xmpp.org/internet-drafts/draft-saintandre-rfc3920bis-06.html#nodeprep
    $vhost->register_hook( "CheckUsername", sub {
        my ($vh, $cb, $username) = shift;

        ### reject it unless it matches what we want
        unless ($username =~ /^[\w-]+$/) {
            $cb->reject;
            return;
        } 

        $cb->accept;
        return;
    });
}

1;
