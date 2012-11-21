#! c:\perl\bin\perl.exe
#------------------------------------------------------------------------------------------------------------------------
# regkeval
# The aim is to help forensic analysts in the triage phase when reviewing the Windows registry by
# inspecting keys of interest, e.g. the registry keys and values involved in malware persistence.
#
# Three arguments are required: name of the task, full path to System and Software hives and full
# path to all users hives.
# e.g.: perl regkeval.pl mytask001 d:\cases\C1\hives d:\cases\C1\hives\users
#       perl regkeval.pl mytask001 d:\cases\C2\allhives d:\cases\C2\allhives
#
# System, software and ntuser hives must contain those words in their own file names.
# The selection of the CurrentControlSet is made reading the registry.
# In order to assist the analyst when reviewing the output the tool automatically retrieves this
# information of any CLSID contained in the data of a value: 
#    InprocHandler32,InprocServer32,LocalServer32,ProgID - Default values
#
# The output consist of three files:
#   Raw output: all registry values retrieved.
#   Revised output: like the raw output plus the calification of the data based on the information
#                   contained in "regkeval_val_malw_espec.tsv" and "regkeval_val_justif.tsv".
#   HTML output: For easy inspection of results.
#
# The output is classified as:
#    Cero - Known values. (Green).
#    Uno - Unknown values. (Gold).
#    Dos - Malware values. (Red).
#    Tres - Differs from the known value. (Red on white).
#    Cuatro - Special values of interest. (Blue on yellow).
#
# The classification is based on the values provided in the files "regkeval_val_justif.tsv" and 
# "regkeval_val_malw_espec.tsv".
# All values in "regkeval_val_justif.tsv" are Cero class and the match must be exact to get it out.
# All values in "regkeval_val_malw_espec.tsv" have their own classification and the match is based 
# only in the value from the column "Indicator".
#
# List of possible filters for retrieving data from values in subkeys of the hive:
#    :::vk:::  - Retrieves all values and keys
#    :::v:::   - Retrieves all values
#    :::*:::   - Any key
#    :::*any_word*:::   - Filter keys containing "any_word"
#    value1&&value2&&value3... - Filter values
# The filters must end with the value/s to retrieve.
#
#
# Files needed:
# 
# regkeval_html.dat - Main part of the html output.
# regkeval_val_malw_espec.tsv - List of known malware values of interest.
#                              You must maintain the format when modifiying the content.
# regkeval_val_justif.tsv - List of known good values that can be discarded at this moment. Currently the list is
#                           made with those values that are expected to remain unchanged over the time since
#                           installation (Ref. http://gotosec.blogspot.com). 
#                           You must maintain the format when modifiying the content.
# regkeval_HKLM.csv - List of HKLM of interest. You must maintain the format when modifiying the content.
# regkeval_HKU.csv - list of HKU values of interest. You must maintain the format when modifiying the content.
#
# Versions:
# v3.1.5 First public version.
# v3.2.0 New classification value based on the negative match of the regkeval_val_justif.tsv.
#
# Author: Ignacio J. Pérez J., nachpj@gmail.com
# 
# This software is released via the GPL v3.0 license:
# http://www.gnu.org/licenses/gpl.html
#------------------------------------------------------------------------------------------------------------------------

use warnings;
use strict;
use Parse::Win32Registry qw(:REG_ hexdump
							unpack_unicode_string);
use File::Copy;
my $reg_count = 0;
my $startime = time;
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
my $start = sprintf("%4d%02d%02d%02d%02d%02d",($year + 1900),($mon+1),$mday,$hour,$min,$sec);
my $task_name = shift or die "Name of the task?";
my $dirhivesM = shift or die "Path to system and software hives?";
my $dirhivesU = shift or die "Path to User hives?";
my @softwarehive = buscahive($dirhivesM,"software");
my @systemhive = buscahive($dirhivesM,"system");
my @userhives = buscahive($dirhivesU,"ntuser");
my @values_clsid = split(",","InprocHandler32,InprocServer32,LocalServer32,ProgID");
my $CLSID_pattern = '\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}';
my $output_file = $task_name."\\".$task_name."_".$start.".tsv";
mkdir $task_name;
print "\nSystem, software and ntuser hives must contain those words in their own file names.\n\n";
open( OUTPUT, ">:utf8", $output_file ) or die "Can't write new file: $!";
	my @keysBuscadas;
	### HKLM #######################
	open (F,"<regkeval_HKLM.csv") or die "Error opening HKLM.csv: $!\n";
		while(<F>) {
				chomp;
				push(@keysBuscadas, $_);
		}
	close(F);
	my $reg_soft = Parse::Win32Registry->new($softwarehive[0]) or die "'@softwarehive' is not a registry file\n";
	my $root_key_soft = $reg_soft->get_virtual_root_key or die "Could not get root key of 'pop(@softwarehive)'\n";
	my $clsid_key = $root_key_soft->get_subkey("Classes\\CLSID");

	my $reg_sys = Parse::Win32Registry->new($systemhive[0]) or die "'@systemhive' is not a registry file\n";
	my $root_key_sys = $reg_sys->get_virtual_root_key or die "Could not get root key of 'pop(@systemhive)'\n";

	my $keyaux = $root_key_sys->get_subkey("Select");
	my $current_value = $keyaux->get_value("Current");
	my $ccs_name = sprintf("ControlSet%03d", $current_value->get_data);
	proc_registro();
	## HKU ###########################
	my $root_key_hku;
	my $clsid_key_hku;
	foreach my $user (@userhives) {
		undef(@keysBuscadas);
		open (F,"<regkeval_HKU.csv") or die "Error opening HKU.csv: $!\n";
			while(<F>) {
				chomp;
				push(@keysBuscadas, $_);
			}
		close(F);
		print OUTPUT $user =~ /\\([^\\]*$)/,"\t","\t","\t","\t","cinco","\n";
		my $reg_hku = Parse::Win32Registry->new($user) or die "'$user' is not a registry file\n";
		$root_key_hku = $reg_hku->get_virtual_root_key or die "Could not get root key of '$user'\n";
		$clsid_key_hku = $root_key_hku->get_subkey("Software\\Classes\\CLSID");
		proc_registro();
	}
close(OUTPUT);
###################################
my $first_part = time - $startime;
print "Searching time: $first_part s\n";
print "Keys and Values checked: $reg_count \n";
print "Now starts the classification of the output. \n";
$first_part = time;
## Classification #####################
my $old = $output_file;
my $output_file_rev = $output_file."_rev.tsv";
open (F,"<regkeval_val_justif.tsv") or die "Error opening regkeval_val_justif.tsv. \n";
	my @a=<F>;
close(F);
my %justifis;
foreach my $justif (@a) {
	$justif =~ s/[\x0A\x0D]//g;
	my @troceado = split(/\t/, $justif);
	$troceado[2] = "" if not exists $troceado[2]; # There are undefined "Default" values
	$justifis{ ($troceado[0]."\t".$troceado[1]) } = $troceado[2];
}
open (Malw,"<regkeval_val_malw_espec.tsv") or die "Error opening regkeval_val_malw_espec.tsv. \n";
	my @val_malw=<Malw>;
close(Malw);
open(OLD, "<$old");
open(NEW, ">$output_file_rev");
	while (<OLD>) {
		my $descon = "1";
		chomp;
		my $linea_old = $_;
		foreach my $malo (@val_malw) {
			my @row = split(/\t/, $malo);
			if ($linea_old =~ /\Q$row[0]\E/) {
				my $aux = " [Match: ".$row[0]."][Info: ".$row[1]."]";
				$linea_old =~ s/(.*)\t$/$1$aux\t/;
				print NEW $linea_old."$row[2]"; 
				$descon = "0";
				last;
			}
		}
		if ($descon) {
			my @linea_part = split(/\t/,$linea_old);
			my $part_d;
			if ($linea_part[1]) {
				my $part_kv = $linea_part[0]."\t".$linea_part[1];
				if ($linea_part[2]) { $part_d = $linea_part[2]} else { $part_d = "" };
				if (exists $justifis{$part_kv}) {
					if ($justifis{$part_kv} eq $part_d) {
						print NEW $linea_old."cero\n"; 
						$descon = "0";
					} else {
						my $susp = " [Expected value: ".$justifis{$part_kv}."]";
						$linea_old =~ s/(.*)\t$/$1$susp\t/;
						print NEW $linea_old."tres\n"; 
						$descon = "0";
					}
				}
			}
		}
		if ($descon) {
			print NEW $linea_old."uno\n";  
		}
	}
close(OLD) or die "can't close $old: $!";
close(NEW) or die "can't close $output_file_rev: $!";
### HTML output ######################
my $output_html = $output_file.".html";
my $input_file= $output_file_rev;
my $end_file = "</TABLE> </BODY> </HTML>";
copy("regkeval_html.dat",$output_html) or die "Check regkeval_html.dat: $!";
open(I, "<$input_file") || die("Couldn't open $input_file\n");
open(O, ">>$output_html");
	chomp(my @whole_file=<I>);
	foreach my $line (@whole_file) {
		# next if ($one_line =~ m/^\s*$/); #ignore blank lines
		# next if ($one_line =~ m/^#/); #ignore lines starting with "#"
		my @record = split(/\t/, $line);
# Heredoc with the results.
print O <<regkeval;
	<tr class="$record[4]">
	<td class="min">$record[0]</td>
	<td>$record[1]</td>
	<td>$record[2]</td>
	<td>$record[3]</td>
	</tr>
regkeval
#end of heredoc.
	}
	print O $end_file;
close(I);
close(O);
## sub,s ################################
sub buscahive {
	my $pathhive = shift;
	my $buscado = shift;
	my @files;
	opendir (DIR,$pathhive) or die "Path to system and software hives not found.";
		while (my $file = readdir(DIR)) {
			next unless (-f "$pathhive/$file");
			if ($file =~ /$buscado/i) {
				push (@files,$pathhive . "\\" . $file );
			}
		}
	closedir(DIR);
	return @files;
}
sub proc_registro {
	my $origen;
	my $root_key;
	foreach my $keyComodin (@keysBuscadas) {
	print OUTPUT $keyComodin,"\t","\t","\t","\t","tres","\n";
	print $keyComodin,"\n";
			if ($keyComodin =~ /HKU\\(.*),.*/) { $root_key = $root_key_hku; $keyComodin = $1; }
			if ($keyComodin =~ /HKLM\\Software\\(.*),.*/) { $root_key = $root_key_soft; $keyComodin = $1; }
			if ($keyComodin =~ /HKLM\\System\\ControlSet(.*),.*/) { $root_key = $root_key_sys; $keyComodin = $ccs_name.$1; }
			if ( $keyComodin =~ /([^:::]*)\\:::.*/ ) {
				$origen = $1;
			} else {
				$keyComodin =~ /(.*)\\/;
				$origen = $1;
			}
			$keyComodin =~ s/:::\*:::/[^\\\\]\*/g;
			$keyComodin =~ s/:::\*/[^\\\\]\*/g;
			$keyComodin =~ s/\*:::/[^\\\\]\*/g;
			$keyComodin =~ s/&&/,/g;
			$keyComodin =~ s/(.*)\\/$1;/;
			$keyComodin =~ s/\\/\\\\/g;
			$keyComodin =~ /(.*);(.*)/;
			my $keybuscada = $1;
			my $valoresbuscados = $2;
			if (my $keyorigen = $root_key->get_subkey($origen)) {
				obtain_values($keyorigen,$keybuscada,$valoresbuscados);
			}
	}
}
sub obtain_values {
		$reg_count +=1;
        my $key = shift;
        my $buscada = shift;
        my $valoresbuscados = shift;
        my $matching_key = "";
        my %matching_values = ();
        my @valbuscados;
        if ($key->get_path =~ /\\$buscada$/i) {
                $matching_key = $key;
				my $key_timestamp = $matching_key->get_timestamp_as_string;
                if ($valoresbuscados =~ /^:::v/) {
					if ($valoresbuscados eq ":::vk:::") {
						foreach my $k ($key->get_list_of_subkeys){
							my $nuevabuscada = $buscada . "\\\\" . $k->get_name();
							obtain_values($k,$nuevabuscada,$valoresbuscados);
						}
					}
					my @vals = $key->get_list_of_values();
					foreach my $v (@vals) {
						push(@valbuscados,$v->get_name());
					}
                } elsif ($valoresbuscados eq ":::v:::") {
					my @vals = $key->get_list_of_values();
					foreach my $v (@vals) {
						push(@valbuscados,$v->get_name());
					}
				}	else {
                        @valbuscados = split(",",$valoresbuscados);
                }
                foreach my $valor (@valbuscados) {
					$reg_count +=1;
					my $valorV = $valor;
					if ($valorV eq "") { $valorV = "Default"};
					if ($valor eq "Default") { $valor = ""};
					if (defined $key->get_value($valor)) {
						my $result_data = $key->get_value($valor)->get_data();
						if ($key->get_value($valor)->get_type_as_string() =~ /BINARY/) {
							my $string = $result_data;
							$string =~ s/[[:^print:]]//g;
							$string =~ s/</&lt/g;
							$string =~ s/>/&gt/g;
							print OUTPUT $matching_key->get_path()," [BINARY]\t",$valorV,"\t",$string,"\t",$key_timestamp,"\t","\n";
						} else {
							print OUTPUT $matching_key->get_path(),"\t",$valorV,"\t",$result_data,"\t",$key_timestamp,"\t","\n";
						}
						if ($result_data =~ /.*($CLSID_pattern).*/) {
							if (defined($clsid_key_hku)) {
								my $clsid_path = "Software\\Classes\\CLSID\\".$1;
								my $subkey_clsid_data = $root_key_hku->get_subkey($clsid_path);
									if (defined $subkey_clsid_data) {
										if (defined $subkey_clsid_data->get_value("")) {
											my $clsid_time = $subkey_clsid_data->get_timestamp_as_string;
											print OUTPUT $subkey_clsid_data->get_path,"\t","Default","\t",$subkey_clsid_data->get_value("")->get_data,"\t",$clsid_time,"\t","\n";
										}
									}
								foreach my $pet (@values_clsid) {
									if (defined $subkey_clsid_data) {
										obtain_values($subkey_clsid_data,$pet,"Default");
									}
								}
							}
							if (defined($clsid_key)) {
								my $clsid_path = "Classes\\CLSID\\".$1;
								my $subkey_clsid_data = $root_key_soft->get_subkey($clsid_path);
									if (defined $subkey_clsid_data) {
										if (defined $subkey_clsid_data->get_value("")) {
											my $clsid_time = $subkey_clsid_data->get_timestamp_as_string;
											print OUTPUT $subkey_clsid_data->get_path,"\t","Default","\t",$subkey_clsid_data->get_value("")->get_data,"\t",$clsid_time,"\t","\n";
										}
									}
								foreach my $pet (@values_clsid) {
									if (defined $subkey_clsid_data) {
										obtain_values($subkey_clsid_data,$pet,"Default");
									}
								}
							}
						}
					}
                }
        }
        foreach my $subkey ($key->get_list_of_subkeys) {
                obtain_values($subkey,$buscada,$valoresbuscados);
        }
}
##################################
my $second_part = time - $first_part;
my $duration = time - $startime;
print "Classification time: $second_part s\n";
print "Total execution time: $duration s\n";
print <<regkeval;
	Raw output: $output_file
	Revised output: $output_file_rev
	HTML revised output: $output_html
regkeval
