package Net::Discident;

use Modern::Perl;
use Digest::MD5     qw( md5_hex );
use File::Find;
use File::stat;
use HTTP::Lite;
use JSON;

use constant BASE_URI => 'http://discident.com/v1';


sub new {
    my $class = shift;
    my $path  = shift;
    
    my $self = {};
    bless $self, $class;
    
    $self->fingerprint( $path );
    
    return $self;
}

sub fingerprint {
    my $self        = shift;
    my $path        = shift;
    my $fingerprint = shift;
    
    return $self->ident()
        if !defined $fingerprint && !defined $path;
    
    $fingerprint = $self->fingerprint_files( $path )
        if !defined $fingerprint;
    
    # discident fingerprints are uppercase and hyphenated hex md5s
    my $md5 = uc md5_hex( $fingerprint );
    $md5 =~ s{(.{8})(.{4})(.{4})(.{4})(.*)}{$1-$2-$3-$4-$5};
    
    $self->{'ident'} = $md5;
    
    return $md5;
}
sub ident {
    my $self  = shift;
    my $ident = shift;
    
    $self->{'ident'} = $ident
        if defined $ident;
    
    return $self->{'ident'};
}
sub query {
    my $self  = shift;
    my $ident = shift // $self->ident();
    my $raw   = shift // 0;
    
    my $uri  = $self->query_url( $ident );
    my $http = HTTP::Lite->new();
    my $code = $http->request( $uri )
        or die "Unable to fetch ident: $!";
    
    die "Unable to fetch ident: HTTP $code"
        unless 200 == $code;
    
    return $http->body()
        if $raw;
    
    return from_json $http->body()
}
sub query_url {
    my $self  = shift;
    my $ident = shift // $self->ident();
    
    return sprintf "%s/%s/", BASE_URI, $ident;
}

sub fingerprint_files {
    my $self = shift;
    my $path = shift;
    
    my $long_fingerprint;
    
    my $stat_file = sub {
        return if -d $_;

        my $stat = stat $_;
        substr $_, 0, length( $path ), '';
        
        $long_fingerprint .= sprintf(
            ":%s:%lld",
                $_,
                $stat->size,
        );
    };
    
    find(
        {
            wanted   => $stat_file,
            no_chdir => 1,
        },
        $path,
    );
    
    return $long_fingerprint;
}

1;

__END__

=head1 NAME 

Net::Discident - determine the fingerprint of a DVD

=head1 SYNOPSIS

...
