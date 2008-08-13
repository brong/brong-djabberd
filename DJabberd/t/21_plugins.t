#!/usr/bin/perl
use strict;
use lib         't/lib';
use Test::More  'no_plan';

# Vhost generates warnings when some standard plugins aren't loaded.
# we know about this, but don't want to spew warnings during 'make test',
# which are not relevant.
# Tried setting the loglevel lower just during the server start, but that
# did not seem to affect the loglevel that's known in Vhost.pm. So, we
# up it here globally for this test --kane
BEGIN { $ENV{LOGLEVEL} = 'ERROR' }

require 'djabberd-test.pl';

use Data::Dumper;
$Data::Dumper::Indent = 1;

# some plugins can be implicitly loaded, so dont do any absolute number checks.
my @Tests = (
    # test1: no plugins
    [ [ ],                  # list of plugins to provide on start    
      { 'Foo',      => 0,   # query + expected number of objects
        'Djabberd'  => 0,
      }
    ],
    
    # test2, some default plugins
    [ [ DJabberd::Delivery::Local->new,
        DJabberd::Delivery::S2S->new,
      ],
      { 'DJabberd::Delivery::Local' => 1,
        'DJabberd::Delivery::S2S'   => 1,
        'DJabberd::Delivery'        => 2,   # local + s2s
      }
    ],     
    
    # test3, some plugins used in the djabberd-test.pl file
    [ [ DJabberd::Authen::AllowedUsers->new(
            policy => "deny", allowedusers => [qw(partya)] ),
        DJabberd::Authen::AllowedUsers->new(
            policy => "deny", allowedusers => [qw(partyb)] ),            
        DJabberd::Authen::StaticPassword->new(password => "password"),
        DJabberd::RosterStorage::InMemoryOnly->new(),
      ],
      { 'Djabberd',                         => 0, # nothing should be ISA DJabberd
        'DJabberd::RosterStorage',          => 1,
        'DJabberd::Authen::StaticPassword'  => 1,
        'DJabberd::Authen::AllowedUsers'    => 2,
        'DJabberd::Authen'                  => 3, # staticpassword + allowedusers
      }
    ],   
);  

my $i;
for my $aref (@Tests) {
    my ($plugins, $href) = @$aref;

    # need the Vhost to do the tests on
    my $vhost;
    # damn warnings!
    local $Test::DJabberd::Server::VHOST_CB = sub { $vhost = shift };
    local $Test::DJabberd::Server::VHOST_CB = sub { $vhost = shift };

    # start server 
    my $srv = Test::DJabberd::Server->new( id => ++$i );
    ok( $srv,                   "Server object created" );
    ok( $srv->start($plugins),  "   Server started" );
    ok( $vhost,                 "   Vhost stored via callback" );

    # pretty print test diagnostics
    my $meth = 'find_plugin_object_of_type';
    ok( 1,                      "   Finding plugins via Vhost->$meth" );

    # at the very least we should get back the amount of plugins we gave it
    # in reality, DJabberd is likely to add a few default ones of its own
    my @all = $vhost->$meth;
    cmp_ok( scalar(@all), '>=', scalar(@$plugins),
                                "       Found minimum amount of plugins" );
    
    # run through all our query and expected count pairs
    while (my($query,$expect) = each %$href) {
        ok( 1,                  "       Calling Vhost->$meth( $query )" );

        # first we check the amount of matches
        my @match = $vhost->$meth( $query );
        is( scalar(@match), $expect,
                                "           Found $expect matches: @match" );

        # then inspect every match individually
        for my $obj (@match) {
            isa_ok($obj,$query, "           Object $obj" );
            ok( $vhost->has_plugin_of_type( ref $obj ),
                                "               And vhost knows about it" );
        }
    }        
    
    # shut down the server, so we can start a new one for the next test
    # out of scope will do the trick, but being explicit about it here.
    $srv->kill;
}    
