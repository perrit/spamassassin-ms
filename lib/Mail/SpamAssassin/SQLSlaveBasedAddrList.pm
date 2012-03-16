# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::SQLSlaveBasedAddrList - SpamAssassin SQL Based Auto Whitelist

=head1 SYNOPSIS

    my $factory = Mail::SpamAssassin::SQLSlaveBasedAddrList->new()
    $spamtest->set_persistent_addr_list_factory ($factory);
  ... call into SpamAssassin classes...

SpamAssassin will call:

    my $addrlist = $factory->new_checker($spamtest);
    $entry = $addrlist->get_addr_entry ($addr, $origip);
  ...

=head1 DESCRIPTION

A SQL based persistent address list implementation.

See C<Mail::SpamAssassin::PersistentAddrList> for more information.

Uses DBI::DBD module access to your favorite database (tested with
MySQL, SQLite and PostgreSQL) to store user auto-whitelists.

The default table structure looks like this:
CREATE TABLE awl (
  username varchar(100) NOT NULL default '',
  email varchar(255) NOT NULL default '',
  ip varchar(16) NOT NULL default '',
  count int(11) NOT NULL default '0',
  totscore float NOT NULL default '0',
  signedby varchar(255) NOT NULL default '',
  PRIMARY KEY (username,email,signedby,ip)
) TYPE=MyISAM;

Your table definition may change depending on which database driver
you choose.  There is a config option to override the table name.

This module introduces several new config variables:

user_awl_dsn

user_awl_sql_username

user_awl_sql_password

user_awl_sql_table

user_awl_sql_override_username

see C<Mail::SpamAssassin::Conf> for more information.


=cut

package Mail::SpamAssassin::SQLSlaveBasedAddrList;

use strict;
use warnings;
use bytes;
use re 'taint';

# Do this silliness to stop RPM from finding DBI as required
BEGIN { require DBI;  import DBI; }

use Mail::SpamAssassin::SQLBasedAddrList;
use Mail::SpamAssassin::Logger;

use vars qw(@ISA);

@ISA = qw(Mail::SpamAssassin::SQLBasedAddrList);

=head2 new

public class (Mail::SpamAssassin::SQLSlaveBasedAddrList) new ()

Description:
This method creates a new instance of the SQLBasedAddrList factory and calls
the parent's (PersistentAddrList) new method.

=cut

sub new {
  my ($proto) = @_;
  my $class = ref($proto) || $proto;
  my $self = $class->SUPER::new(@_);
  $self->{class} = $class;
  bless ($self, $class);
  $self;
}

=head2 new_checker

public instance (Mail::SpamAssassin::SQLSlaveBasedAddrList) new_checker (\% $main)

Description:
This method is called to setup a new checker interface and return a blessed
copy of itself.  Here is where we setup the SQL database connection based
on the config values.

=cut

sub new_checker {
  my ($self, $main) = @_;

  # connection to slave database is built up by parent
  my $checker = $self->SUPER::new_checker ($main);
  if (! $checker) {
    return undef;
  }

  my $table = $main->{conf}->{user_awl_master_sql_table} ||
              $main->{conf}->{user_awl_sql_table};

  if (! $main->{conf}->{user_awl_master_dsn} || ! $table) {
    dbg("auto-whitelist: sql-based invalid master config");
    return undef;
  }

  my $dsn    = $main->{conf}->{user_awl_master_dsn};
  my $dbuser = $main->{conf}->{user_awl_master_sql_username} ||
               $main->{conf}->{user_awl_sql_username};
  my $dbpass = $main->{conf}->{user_awl_master_sql_password} ||
               $main->{conf}->{user_awl_sql_password};

  $self = $checker;
  $self->{mdsn} = $dsn;
  $self->{mtablename} = $table;

  my $dbh = DBI->connect ($dsn, $dbuser, $dbpass, {'PrintError' => 0});
  if ($dbh) {
    dbg("auto-whitelist: sql-based connected to %s", $dsn);
    $self->{mdbh} = $dbh;
  } else {
    # Do not bail if we can't connect to the master database, we accept loosing
    # some updates to the auto whitelist.
    info("auto-whitelist: sql-based unable to connect to master database" .
         " (%s) : %s", $dsn, DBI::errstr);
    $self->{mdbh} = undef;
  }

  return $self;
}

# get_addr_entry must operate on the slave database, therefore no changes are
# needed

=head2 add_score

public instance (\%) add_score (\% $entry, Integer $score)

Description:
This method adds a given C<$score> to a given C<$entry>.  If the entry was
marked as not existing in the database then an entry will be inserted,
otherwise a simple update will be performed.

NOTE: This code uses a self referential SQL call (ie set foo = foo + 1) which
is supported by most modern database backends, but not everything calling
itself a SQL database.

=cut

sub add_score {
  my ($self, $entry, $score) = @_;
  # only update if master database is available
  if ($self->{mdbh}) {
    my $func = \&Mail::SpamAssassin::SQLBasedAddrList::add_score;
    dbg("auto-whitelist: updating this crap!");
    return $self->_swap_db (@_, $func);
  }

  dbg("auto-whitelist: sql-based add_score/update: master database unvailable");
  return $entry;
}

=head2 remove_entry

public instance () remove_entry (\% $entry)

Description:
This method removes a given C<$entry> from the database.  If the
ip portion of the entry address is equal to "none" then remove any
perl-IP entries for this address as well.

=cut

sub remove_entry {
  my ($self) = @_;
  # only remove if master database is available
  if ($self->{mdbh}) {
    my $func = \&Mail::SpamAssassin::SQLBasedAddrList::remove_entry;
    return $self->_swap_db (@_, $func);
  }

  dbg("auto-whitelist: sql-based remove_entry: master database unavailable");
  return undef;
}

=head2 finish

public instance () finish ()

Description:
This method provides the necessary cleanup for the address list.

=cut

sub finish {
  my ($self) = @_;
  # disconnect from slave database
  $self->SUPER::finish;
  # disconnect from master database
  dbg("auto-whitelist: sql-based finish: disconnected from " . $self->{mdsn});
  $self->{mdbh}->disconnect ();
}

=head2 _swap_db

private instance (*) _swap_db (*, Function reference $func)

Description:
Swaps handle to slave database for handle to master database and invokes the
specified function with all of the original arguments except for the function
reference.

=cut

sub _swap_db {
  my ($self) = shift;

  my $last = $#_;
  my $func = $_[$last];
  delete ($_[$last]);

  my $dbh = $self->{dbh};
  my $table = $self->{tablename};
  $self->{dbh} = $self->{mdbh};
  $self->{tablename} = $self->{mtablename};

  my $entry = &$func (@_) || undef;

  $self->{dbh} = $dbh;
  $self->{tablename} = $table;

  return $entry;
}

1;
