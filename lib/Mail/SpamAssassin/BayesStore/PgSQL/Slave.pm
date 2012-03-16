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

Mail::SpamAssassin::BayesStore::PgSQL::Slave

=head1 SYNOPSIS

=head1 DESCRIPTION

This module implements a PostgreSQL specific bayesian storage module for
master-slave setups.

It subclasses Mail::SpamAssassin::BayesStore::PgSQL and uses as much of it's
code as possible by swapping out database handle references before invoking the
method implemented in the SUPER pseudo-class.

=cut

package Mail::SpamAssassin::BayesStore::PgSQL::Slave;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::BayesStore::PgSQL;
use Mail::SpamAssassin::Logger;

use vars qw ( @ISA );

@ISA = qw ( Mail::SpamAssassin::BayesStore::PgSQL );

use constant HAS_DBI => eval { require DBI; };

BEGIN { require DBD::Pg; import DBD::Pg qw(:pg_types); }

=head1 METHODS

=head2 new

public class (Mail::SpamAssassin::BayesStore::PgSQL::Slave) new (Mail::Spamassassin::Plugin::Bayes $bayes)

Description:
This methods creates a new instance of the Mail::SpamAssassin::BayesStore::PgSQL::Slave
object.  It expects to be passed an instance of the Mail::SpamAssassin:Bayes
object which is passed into the Mail::SpamAssassin::BayesStore parent object.

=cut

sub new {
  my $class = shift;
  $class = ref ($class) || $class;

  my $self = $class->SUPER::new (@_);

  $self->{_mdbh} = undef; # master database handle
  $self->{_mdsn} = $self->{bayes}->{conf}->{bayes_sql_master_dsn};
  $self->{_mdbuser} = $self->{bayes}->{conf}->{bayes_sql_master_username} ||
                      $self->{bayes}->{conf}->{bayes_sql_username};
  $self->{_mdbpass} = $self->{bayes}->{conf}->{bayes_sql_master_password} ||
                      $self->{bayes}->{conf}->{bayes_sql_password};
  $self->{_mdbswap} = 1;

  return $self;
}

=head2 tie_db_writable

public instance (Boolean) tie_db_writable ()

Description:
This method ensures that the database connection is properly setup
and working. If necessary it will initialize a users bayes variables
so that they can begin using the database immediately.

=cut

sub tie_db_writable {
  my ($self) = @_;

  if (! $self->SUPER::tie_db_writable ()) {
    $self->untie_db ();
    return 0;
  }

  return 1 if ($self->{_mdbh});

  # SpamAssassin opens a new database connection per incoming message, because
  # of that there is no point in implementing some kind of retry interval

  $self->{db_writable_p} = 0;

  if ($self->_connect_db ()) {
    $self->{mdb_version} = $self->_get_db_version ();
    dbg("bayes: found bayes master db version " . $self->{mdb_version});

    if ($self->{mdb_version} != $self->DB_VERSION) {
      warn("bayes: master database version " . $self->{mdb_version} . " is different than we understand (".$self->DB_VERSION."), aborting!");
      $self->{_mdbh}->disconnect ();
      $self->{_mdbh} = undef;
    }

    if ($self->{_mdbh} && ! $self->_initialize_db (1)) {
      dbg("bayes: unable to initialize master database for " . $self->{_username} . " user, aborting!");
      $self->untie_db ();
    }
  }

  if ($self->{_mdbh}) {
    $self->{db_writable_p} = 1;
    return 1;
  }

  return 0;
}

=head2 untie_db

public instance () untie_db ()

Description:
Disconnects from master and slave databases.

=cut

sub untie_db {
  my ($self) = (@_);

  $self->SUPER::untie_db ();

  if ($self->{_mdbh}) {
    $self->{_mdbh}->disconnect ();
    $self->{_mdbh} = undef;
  }
}

sub expire_old_tokens {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::expire_old_tokens;
  return $self->_swap_db ($func, @_);
}

sub seen_get {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::SQL::seen_get;
  return ($self->_swap_db ($func, @_))[0];
}

sub seen_put {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::seen_put;
  return $self->_swap_db ($func, @_);
}

sub seen_delete {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::seen_delete;
  return $self->_swap_db ($func, @_);
}

sub dump_db_toks {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::SQL::dump_db_toks;
  return $self->_swap_db ($func, @_);
}

sub set_last_expire {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::set_last_expire;
  return $self->_swap_db ($func, @_);
}

sub tok_count_change {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::tok_count_change;
  return $self->_swap_db ($func, @_);
}

sub multi_tok_count_change {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::SQL::multi_tok_count_change;
  return $self->_swap_db ($func, @_);
}

sub nspam_nham_change {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::nspam_nham_change;
  return $self->_swap_db ($func, @_);
}

sub tok_touch {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::tok_touch;
  return $self->_swap_db ($func, @_);
}

sub tok_touch_all {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::tok_touch_all;
  return $self->_swap_db ($func, @_);
}

sub cleanup {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::cleanup;
  return $self->_swap_db ($func, @_);
}

sub clear_database {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::PgSQL::clear_database;
  return $self->_swap_db ($func, @_);
}

sub backup_database {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::SQL::backup_database;
  return $self->_swap_db ($func, @_);
}

sub restore_database {
  my $self = shift;
  my $func = \&Mail::SpamAssassin::BayesStore::SQL::restore_database;
  return $self->_swap_db ($func, @_);
}

=head2 db_readable

public instance (Boolean) db_readable()

Description:
This method returns a boolean value indicating if the database is in a
readable state.

=cut

sub db_readable {
  my ($self) = @_;

  return defined ($self->{_dbh}) ? 1 : 0;
}

=head2 db_writable

public instance (Boolean) db_writeable()

Description:
This method returns a boolean value indicating if the database is in a
writable state.

=cut

sub db_writable {
  my ($self) = @_;

  return defined ($self->{_mdbh} && $self->{db_writable_p}) ? 1 : 0;
}

=head1 Private Methods

=head2 _swap_db

private instance (\@) _swap_db ($conn, $func, ...)

Description:
Swap active database handle for given database handle.

Implemented for brevity and to centralize logic, designed to stay out of the
way.

=cut

sub _swap_db {
  my $self = shift;
  my $func = shift;

  my $dbh = undef;
  my $swap = 0;

  # _dbswap member was introduced to force the use of the same database handle
  # on subsequent calls for as long as we didn't return from this invocation of
  # _swap_db
  if ($self->{_mdbswap}) {
    $dbh = $self->{_dbh};
    $swap = 1;
    $self->{_dbh} = $self->{_mdbh};
    $self->{_mdbswap} = 0;
  }

  my @ret = &$func ($self, @_);

  if ($swap) {
    $self->{_dbh} = $dbh;
    $self->{_mdbswap} = 1;
  }

  return (@ret);
}

=head2 _caller_package_subroutine

=cut

sub _caller_package_subroutine {
  my $caller = (caller (2))[3] || '';
  my $pos = rindex ($caller, '::');
  my $pkg = substr ($caller, 0, $pos);
  my $sub = substr ($caller, $pos + 2);

  return ($pkg, $sub);
}

=head2 _connect_db

private instance (Boolean) _connect_db ()

Description:
Connects to master and slave databases.

=cut

sub _connect_db {
  my ($self) = @_;
  my ($pkg, $sub) = $self->_caller_package_subroutine ();

  my $rdwr = ($pkg eq __PACKAGE__ && $sub eq 'tie_db_writable') ? 1 : 0;
  my $ret = 0;

  # tie_db_writable first invokes tie_db_writable in it's parent, that is where
  # _connect_db connects to the slave database
  if ($rdwr) {
    my $dbh = DBI->connect ($self->{_mdsn},
                            $self->{_mdbuser},
                            $self->{_mdbpass},
                            {PrintError => 0, AutoCommit => 0});
    if ($dbh) {
      dbg("bayes: connection to master database established");
      $self->{_mdbh} = $dbh;
      # _esc_prefix is used for queries against the master database, therefore
      # it is not necessary to keep two copies
      if ($dbh->{pg_server_version} >= 80100) {
        $self->{_esc_prefix} = 'E';
      } else {
        $self->{_esc_prefix} = '';
      }
      $ret = 1;
    } else {
      dbg("bayes: unable to connect to master database: " . DBI->errstr ());
      $self->{_mdbh} = undef;
      $ret = 0;
    }
  } else {
    $ret = $self->SUPER::_connect_db ();
  }

  return $ret;
}

=head2 _get_db_version

private instance (Integer) _get_db_version ()

Description:
Gets the current version of the database from the special global vars tables.

=cut

sub _get_db_version {
  my ($self) = @_;
  my ($pkg, $sub) = $self->_caller_package_subroutine ();

  my $dbh = ($pkg eq __PACKAGE__) ? $self->{_mdbh} : $self->{_dbh};

  return 0 if (! defined ($dbh));
  return $self->{_mdb_version_cache}
    if ($pkg eq __PACKAGE__ && defined ($self->{_mdb_version_cache}));
  return $self->{_db_version_cache}
    if ($pkg ne __PACKAGE__ && defined ($self->{_db_version_cache}));

  my $sql = "SELECT value FROM bayes_global_vars WHERE variable = 'VERSION'";
  my $sth = $dbh->prepare_cached ($sql);

  if (! defined ($sth) || ! $sth->execute ()) {
    dbg("bayes: _get_db_version: SQL error: " . $dbh->errstr ());
    return 0;
  }

  my ($version) = $sth->fetchrow_array ();

  $sth->finish ();

  if ($pkg eq __PACKAGE__) {
    $self->{_mdb_version_cache} = $version;
  } else {
    $self->{_db_version_cache} = $version;
  }

  return $version;
}

=head2 _initialize_db

private instance (Boolean) _initialize_db ()

Description:
This method will check to see if a user has had their bayes variables
initialized. If not then it will perform this initialization.

Note that this method differs from the original in
Mail::SpamAssassin::BayesStore::SQL in that it only performs the initialization
only if it's invoked from Mail::SpamAssassin::BayesStore::PgSQL::Slave.

=cut

sub _initialize_db {
  my ($self, $create_entry_p) = @_;
  my ($pkg, $sub) = $self->_caller_package_subroutine ();

  return 0 if (! defined ($self->{_dbh}));
  return 0 if (! defined ($self->{_username}) || $self->{_username} eq '');

  if ($self->{bayes}->{conf}->{bayes_sql_username_authorized}) {
    my $services = { 'bayessql' => 0 };
    $self->{bayes}->{main}->call_plugins("services_allowed_for_username",
					 { services => $services,
					   username => $self->{_username},
					   conf => $self->{bayes}->{conf},
					 });
    
    unless ($services->{bayessql}) {
      dbg("bayes: username not allowed by services_allowed_for_username plugin call");
      return 0;
    }
  }

  my $sql = "SELECT id FROM bayes_vars WHERE username = ?";
  my $sth = $self->{_dbh}->prepare_cached($sql);

  if (! defined ($sth) || ! $sth->execute ($self->{_username})) {
    dbg("bayes: _initialize_db: SQL error: " . $self->{_dbh}->errstr());
    return 0;
  }

  my ($id) = $sth->fetchrow_array();

  goto skip if ($id);
  goto skip if (! $create_entry_p);
  goto skip if (! $self->{_mdbh});
  goto skip if ($pkg ne __PACKAGE__);

  $sql = 'INSERT INTO bayes_vars (username) VALUES (?)';

  # Since multiple hosts can connect to the same master database, we need to
  # analyze the error message. If the insert failed because the username
  # already exists, we ignore the error and hope for the best further down
  # the road.
  if ($self->{_mdbh}->do ($sql, undef, $self->{_username})) {
    $self->{_mdbh}->commit ();
  } else {
    # For PostgreSQL specific error codes see:
    # http://www.postgresql.org/docs/current/static/errcodes-appendix.html
    # We're looking for 23505, unique_violation.
    my $state = $self->{_mdbh}->state ();
    if (index ($state, '23505') < 0) {
      dbg("bayes: _initialize_db: SQL error: " . $self->{_mdbh}->errstr ());
      goto skip;
    }
    # FIXME: allow little time for replication to happen?
  }

  # Figure out what id we inserted the user at.
  if (! $sth->execute ($self->{_username})) {
    dbg("bayes: _initialize_db: SQL error: " . $self->{_dbh}->errstr ());
    return 0;
  }

  ($id) = $sth->fetchrow_array ();

skip:
  $sth->finish ();

  if ($id) {
    dbg ("bayes: using userid: $id");
    $self->{_userid} = $id;
  }

  return 1 if ($id || $pkg ne __PACKAGE__);
  return 0;
}
