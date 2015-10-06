# regkeval
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

