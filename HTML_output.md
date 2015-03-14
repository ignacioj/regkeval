#HTML output color code explained.

# Introduction #

Maybe you can think that there are too much colors in the html output of Regkeval but you must keep in mind that there can be several thousand lines in the output to review.

# Details #

The normal output will be full of green lines meaning that it matches exactly with the value that is expected to find so you can browse very quickly the document.
Whenever the tool finds any mismatch with a value that is included in the file containing the expected values for the system, the regkeval\_val\_justif.tsv file, the line will be displayed as red text on white background and it will append to the time field the expected value as it appears in the regkeval\_val\_justif.tsv file.

When there is a match with any of the keywords contained in the regkeval\_val\_malw\_espec.tsv file the entry is displayed as white on red background if it is classified as malware.
But if it is classified as a special value then it will be displayed as blue on yellow background.
The classification as malware or value of interest can be made by assigning to the corresponding keyword the string "dos" for malware or the string "cuatro" for values of interest in the regkeval\_val\_malw\_espec.tsv file.
In both cases the information included in the regkeval\_val\_malw\_espec.tsv file will be appended to the time field in the output.

If there is no info about the value it is displayed as sunset color.

Finally the grey background color is used to display the beginning of the corresponding search path output and the blue background color is used to indicate the beginning of a ntuser.dat file analysis.