Added perl program to get all the service triggers from an offline hive: serv-triggers.pl.
Service triggers can start and stop services containing malware. You have to run it as:
serv-triggers.pl system


---


Regkeval.
The idea is to compare as many registry entries as I know that can be used for malware persistence against both a well-known baseline of right and wrong values.

Characteristics:

- Works on offline registry hives.

- The keys and values to search can be defined using wildcards. It can be used to detect anomalies in computers with similar characteristics and configuration.

- Resolves any CLSID obtained in the output.

- Extraction of readable content from binary data.

- Custom selection of keys to retrieve based on filters.

- Custom classification of the output.

- TSV file and colorized html output for easier inspection of results.

- The timestamps of the keys are included in the output.

nachpj@gmail.com
```
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
#    InprocHandler32,InprocServer32,LocalServer32,ProgID - Default values in @values_clsid
#
# The output consist of five files:
#   Raw output: all registry values retrieved.
#   Revised output: like the raw output plus the calification of the data based on the information
#                   contained in "regkeval_val_malw_espec.tsv" and "regkeval_val_justif.tsv".
#   HTML output: For easy inspection of results.
#   Timeline output: tsv and html.
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
#    :::c:::   - Obtain information for the CLSID found in the key name
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
# v3.3   Support for multiple datas for a given value
# v3.4 Added timeline output.
# v3.5 Now you can force to obtain information for CLSID,s found in the Key name.
# Author: Ignacio J. Pérez J., nachpj@gmail.com
# Copyright 2012 Ignacio J. Pérez J., nachpj@gmail.com
# This software is released via the GPL v3.0 license:
# http://www.gnu.org/licenses/gpl.html
```