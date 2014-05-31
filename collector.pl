#!/usr/local/bin/perl -w
use strict;
open (MYFILE, '>collector.txt');
print MYFILE "IPs found active on this system\n";
print MYFILE "===============================\n\n";
my @ssLine = `ss | grep "ESTAB" | awk '{ print \$NF }'`;
#calculates total number of IP adresses shown in the SS command
my $arrayLimit = scalar (@ssLine);
my $i;
my $j;
for ($i = 0; $i < $arrayLimit; $i++)
{
	for ($j = 0; $j < 5; $j++) 	#loop used to chop ":www"
	{
		my $chr;			#palce holder
		$chr = chop($ssLine[$i]);	#chopping
	}	
}
#check for copies and reinitializes new limit
my %hash = map { $_ => 1 } @ssLine;
my @unique = keys %hash;
$arrayLimit = scalar (@unique);
my $ValidDomainName;
my $hostCheck;
my @ValidIP;
my $k;
for ($k = 0; $k < $arrayLimit; $k++)
{	
	my $IPadress = $unique[$k];
	print MYFILE "\t+--------------------------\n";
	print MYFILE "\t|REPORT FOR ip = $IPadress \n";
	$hostCheck = `host $IPadress | grep "domain name pointer"`;
	#^^search and print only valid domain names!!^^	
	my $num = length($hostCheck);
	#^^length of printed object!!^^	
	if ($num != 0) #<< if there is nothing (invalid domiain name)
	{
		push (@ValidIP, $IPadress);
		$ValidDomainName = $hostCheck;
		print MYFILE "\t|\t $ValidDomainName";
		print MYFILE "\t|\t Whois data for ip $IPadress:\n";
		my @IPwhois = `whois $IPadress\n`;
		my $limit1 = scalar (@IPwhois);
		my $x;
		for ($x = 0; $x < $limit1; $x++)
		{
			print MYFILE "\t|\t\t"; #formatting
			print MYFILE $IPwhois[$x];
		}
		my @domainName;
		@domainName = split(/\./, $ValidDomainName);
		my $numm = scalar (@domainName);
		my $finalName = $domainName[$numm-3] . ".";
		$finalName = $finalName . $domainName[$numm -2];
		print MYFILE "\t|\t Whois data for domain $finalName:\n";
		my @WhoisDomain = ` whois $finalName`;
		my $limit2 = scalar (@WhoisDomain);
		my $y;
		for ($y = 0; $y < $limit2; $y++)
		{
			print MYFILE "\t|\t\t"; #formatting
			print MYFILE $WhoisDomain[$y];
		}
		print MYFILE "\t|\t\n";
	}
	else
	{
		print MYFILE "\t|\t No hostname found to be associated with $IPadress\n";
		print MYFILE "\t|\t Whois data for ip $IPadress:\n";
		my @IPwhois = `whois $IPadress\n`;
		my $limit1 = scalar (@IPwhois);
		my $x;
		for ($x = 0; $x < $limit1; $x++)
		{
			print MYFILE "\t|\t\t"; #formatting
			print MYFILE $IPwhois[$x];
		}
	}
	print MYFILE "\t|END REPORT FOR ip = $IPadress \n";
	print MYFILE "\t+--------------------------\n";
}
print MYFILE "\n";
close (MYFILE);
exit;
