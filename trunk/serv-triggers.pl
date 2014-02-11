#! c:\perl\bin\perl.exe
#------------------------------------------------------------------------------------------------------------------------
# serv-triggers
# Get the service triggers when available
# 2014-02-10 - created
#
# Function parseGUID() from shellbags.pl - H. Carvey, keydet89@yahoo.com
#
# References: 
# http://isc.sans.edu/diary/Wipe+the+drive+Stealthy+Malware+Persistence+-+Part+3/15448
# http://msdn.microsoft.com/en-us/library/windows/desktop/dd405512(v=vs.85).aspx
# http://msdn.microsoft.com/en-us/library/windows/hardware/ff553412(v=vs.85).aspx
#
#
# Author: Ignacio .J. Pérez J., nachpj@gmail.com
# Copyright 2012 Ignacio J. Pérez J., nachpj@gmail.com
# This software is released via the GPL v3.0 license:
# http://www.gnu.org/licenses/gpl.html
#------------------------------------------------------------------------------------------------------------------------
use warnings;
use strict;
use Parse::Win32Registry qw(:REG_ hexdump
							unpack_unicode_string);
use File::Copy;
use File::Find;
my $systemhive = shift or die "Path to system hive?";

# Ref: http://msdn.microsoft.com/en-us/library/windows/desktop/dd405512(v=vs.85).aspx
my %type_val = (0x014 => "SERVICE_TRIGGER_TYPE_CUSTOM",
				0x001 => "SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL",
				0x003 => "SERVICE_TRIGGER_TYPE_DOMAIN_JOIN",
				0x004 => "SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT",
				0x005 => "SERVICE_TRIGGER_TYPE_GROUP_POLICY",
				0x002 => "SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY",
				0x006 => "SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT");

my %action_val = (0x01 => "START",
				0x02 => "STOP");
				
my %dataType_val = (0x01 => "SERVICE_TRIGGER_DATA_TYPE_BINARY",
					0x02 => "SERVICE_TRIGGER_DATA_TYPE_STRING",
					0x03 => "SERVICE_TRIGGER_DATA_TYPE_LEVEL",
					0x04 => "SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY",
					0x05 => "SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL");
				
my %subtype_GUID = ("{1f81d131-3fac-4537-9e0c-7e7b0c2f4b55}" => "NAMED_PIPE_EVENT_GUID",
					"{bc90d167-9470-4139-a9ba-be0bbbf5b74d}" => "RPC_INTERFACE_EVENT_GUID",
					"{1ce20aba-9851-4421-9430-1ddeb766e809}" => "DOMAIN_JOIN_GUID",
					"{ddaf516e-58c2-4866-9574-c3b615d42ea1}" => "DOMAIN_LEAVE_GUID",
					"{b7569e07-8421-4ee0-ad10-86915afdad09}" => "FIREWALL_PORT_OPEN_GUID",
					"{a144ed38-8e12-4de4-9d96-e64740b1a524}" => "FIREWALL_PORT_CLOSE_GUID",
					"{659fcae6-5bdb-4da9-b1ff-ca2a178d46e0}" => "MACHINE_POLICY_PRESENT_GUID",
					"{4f27f2de-14e2-430b-a549-7cd48cbc8245}" => "NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID",
					"{cc4ba62a-162e-4648-847a-b6bdf993e335}" => "NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID",
					"{54fb46c8-f089-464c-b1fd-59d1b62c3b50}" => "USER_POLICY_PRESENT_GUID",
					"{6bdd1fc1-810f-11d0-bec7-08002be2092f}" => "BUS1394_CLASS_GUID",
					"{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}" => "GUID_61883_CLASS",
					"{629758ee-986e-4d9e-8e47-de27f8ab054d}" => "GUID_DEVICE_APPLICATIONLAUNCH_BUTTON",
					"{72631e54-78a4-11d0-bcf7-00aa00b7b32a}" => "GUID_DEVICE_BATTERY",
					"{4afa3d52-74a7-11d0-be5e-00a0c9062857}" => "GUID_DEVICE_LID",
					"{3fd0f03d-92e0-45fb-b75c-5ed8ffb01021}" => "GUID_DEVICE_MEMORY",
					"{cd48a365-fa94-4ce2-a232-a1b764e5d8b4}" => "GUID_DEVICE_MESSAGE_INDICATOR",
					"{97fadb10-4e33-40ae-359c-8bef029dbdd0}" => "GUID_DEVICE_PROCESSOR",
					"{4afa3d53-74a7-11d0-be5e-00a0c9062857}" => "GUID_DEVICE_SYS_BUTTON",
					"{4afa3d51-74a7-11d0-be5e-00a0c9062857}" => "GUID_DEVICE_THERMAL_ZONE",
					"{0850302a-b344-4fda-9be9-90576b8d46f0}" => "GUID_BTHPORT_DEVICE_INTERFACE",
					"{fde5bba4-b3f9-46fb-bdaa-0728ce3100b4}" => "GUID_DEVINTERFACE_BRIGHTNESS",
					"{5b45201d-f2f2-4f3b-85bb-30ff1f953599}" => "GUID_DEVINTERFACE_DISPLAY_ADAPTER",
					"{2564aa4f-dddb-4495-b497-6ad4a84163d7}" => "GUID_DEVINTERFACE_I2C",
					"{6bdd1fc6-810f-11d0-bec7-08002be2092f}" => "GUID_DEVINTERFACE_IMAGE",
					"{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}" => "GUID_DEVINTERFACE_MONITOR",
					"{bf4672de-6b4e-4be4-a325-68a91ea49c09}" => "GUID_DEVINTERFACE_OPM",
					"{1ad9e4f0-f88d-4360-bab9-4c2d55e564cd}" => "GUID_DEVINTERFACE_VIDEO_OUTPUT_ARRIVAL",
					"{1ca05180-a699-450a-9a0c-de4fbe3ddd89}" => "GUID_DISPLAY_DEVICE_ARRIVAL",
					"{4d1e55b2-f16f-11cf-88cb-001111000030}" => "GUID_DEVINTERFACE_HID",
					"{884b96c3-56ef-11d1-bc8c-00a0c91405dd}" => "GUID_DEVINTERFACE_KEYBOARD",
					"{378de44c-56ef-11d1-bc8c-00a0c91405dd}" => "GUID_DEVINTERFACE_MOUSE",
					"{2c7089aa-2e0e-11d1-b114-00c04fc2aae4}" => "GUID_DEVINTERFACE_MODEM",
					"{cac88484-7515-4c03-82e6-71a87abac361}" => "GUID_DEVINTERFACE_NET",
					"{86e0d1e0-8089-11d0-9ce4-08003e301f73}" => "GUID_DEVINTERFACE_COMPORT",
					"{97f76ef0-f883-11d0-af1f-0000f800845c}" => "GUID_DEVINTERFACE_PARALLEL",
					"{811fc6a5-f728-11d0-a537-0000f8753ed1}" => "GUID_DEVINTERFACE_PARCLASS",
					"{4d36e978-e325-11ce-bfc1-08002be10318}" => "GUID_DEVINTERFACE_SERENUM_BUS_ENUMERATOR",
					"{53f56312-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_CDCHANGER",
					"{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_CDROM",
					"{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_DISK",
					"{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_FLOPPY",
					"{53f56310-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_MEDIUMCHANGER",
					"{53f5630a-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_PARTITION",
					"{2accfe60-c130-11d2-b082-00a0c91efb8b}" => "GUID_DEVINTERFACE_STORAGEPORT",
					"{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_TAPE",
					"{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_VOLUME",
					"{53f5630c-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_DEVINTERFACE_WRITEONCEDISK",
					"{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" => "GUID_IO_VOLUME_DEVICE_INTERFACE",
					"{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" => "MOUNTDEV_MOUNTED_DEVICE_GUID",
					"{095780c3-48a1-4570-bd95-46707f78c2dc}" => "GUID_AVC_CLASS",
					"{616ef4d0-23ce-446d-a568-c31eb01913d0}" => "GUID_VIRTUAL_AVC_CLASS",
					"{a5dcbf10-6530-11d2-901f-00c04fb951ed}" => "GUID_DEVINTERFACE_USB_DEVICE",
					"{3abf6f2d-71c4-462a-8a92-1e6861e6af27}" => "GUID_DEVINTERFACE_USB_HOST_CONTROLLER",
					"{f18a0e88-c30c-11d0-8815-00a0c906bed8}" => "GUID_DEVINTERFACE_USB_HUB",
					"{6ac27878-a6fa-4155-ba85-f98f491d4f33}" => "GUID_DEVINTERFACE_WPD",
					"{ba0c718f-4ded-49b7-bdd3-fabe28661211}" => "GUID_DEVINTERFACE_WPD_PRIVATE",
					"{152e5811-feb9-4b00-90f4-d32947ae1681}" => "GUID_DEVINTERFACE_SIDESHOW");

my $reg_sys = Parse::Win32Registry->new($systemhive) or die "'$systemhive' is not a registry file\n";
my $root_key_sys = $reg_sys->get_virtual_root_key or die "Could not get root key of 'pop($systemhive)'\n";
my $keyaux = $root_key_sys->get_subkey("Select");
my $current_value = $keyaux->get_value("Current");
my $cs_current = $current_value->get_data();
my $key_services = $root_key_sys->get_subkey("ControlSet00".$cs_current."\\services");
my @list_services = $key_services->get_list_of_subkeys();

foreach my $serv_name (@list_services) {
	my $serv_path = "ControlSet00".$cs_current."\\services\\".$serv_name->get_name()."\\TriggerInfo";
	my $subkey_trigger = $root_key_sys->get_subkey($serv_path);
	if (defined $subkey_trigger) {
		print "-----------------------------------------------------------------------------\n";
		print $serv_name->get_timestamp_as_string()." - ";
		print "Service: ".$serv_name->get_name()."\n";
		my @list_triggers = $subkey_trigger->get_list_of_subkeys();
		if (scalar (@list_triggers) > 0) {
			foreach my $skey (@list_triggers) {
				print $skey->get_timestamp_as_string()." - ";
				print "\tTrigger ".$skey->get_name()."\n";
				my %content;
				my $list_datas = 0;
				my @vals = $skey->get_list_of_values();
				foreach my $v (@vals) {
					my $name = $v->get_name();
					$content{$name} = $v->get_data();
					if ($name =~ /DataType.*/) {
						$list_datas +=1;
					}
				}
				if (exists $content{Type}) {
					print "\t\tType: ".$type_val{$content{Type}}."\n";
				}
				if (exists $content{Action}) {
					print "\t\tAction: ".$action_val{$content{Action}}."\n";
				}
				if (exists $content{GUID}) {
					my $parse_guid = parseGUID($content{GUID});
					print "\t\tSubtype (GUID): ".$parse_guid."\n";
					if (my $known = $subtype_GUID{$parse_guid}) {
						print "\t\t\tKnown GUID: ".$known."\n";
					} else {
						print "\t\t\tNot known GUID.\n";
					}
				}
				for (my $i = 0; $i < $list_datas; $i++) {
					print "\t\tDataType".$i.": ".$dataType_val{$content{"DataType".$i}}."\n";
					if ($dataType_val{$content{"DataType".$i}} =~ /SERVICE_TRIGGER_DATA_TYPE_BINARY/) {
						print "\t\tData".$i.": ".unpack("H*",$content{"Data".$i})."\n";
					} else {
						print "\t\tData".$i.": ".$content{"Data".$i}."\n";
					}
				}
			}
		}
	}
}

#-----------------------------------------------------------
# parseGUID()
# Takes 16 bytes of binary data, returns a string formatted
# as an MS GUID.
#-----------------------------------------------------------
sub parseGUID {
	my $data     = shift;
  my $d1 = unpack("V",substr($data,0,4));
  my $d2 = unpack("v",substr($data,4,2));
  my $d3 = unpack("v",substr($data,6,2));
	my $d4 = unpack("H*",substr($data,8,2));
  my $d5 = unpack("H*",substr($data,10,6));
  return sprintf "{%08x-%x-%x-$d4-$d5}",$d1,$d2,$d3;
}

#-----------------------------------------------------------
