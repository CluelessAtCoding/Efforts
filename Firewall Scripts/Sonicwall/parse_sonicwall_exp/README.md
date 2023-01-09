# parse_sonicwall_exp.py

I had need to review a firewall config and did not want to pay for a tool so I wrote a script to do some of the heavy lifting for me. 

It decodes and parses the provided Sonicwall exp file and exports some key information out to worksheets in an Excel Spreadsheet. 

It does not parse all the information in the exp file and should definitely be considered a work in progress. I will add some extra categories over time. 

Install the Python requirements with :

- pip install -r requirements.txt

Invoke the script passing the exp filename in the command line:

- ./parse_sonicwall_exp.py ./sonicwall-ABCDEF123456-1999123125959.exp

# parse_sonicwall_v3.py

An updated version of my script, which will now parse decoded export files as well as encoded exp files.

To decode and parse an encoded file:

- ./parse_sonicwall_v3.py ./sonicwall-ABCDEF123456-1999123125959.exp --encoded

To parse an already decoded file:

- ./parse_sonicwall_v3.py ./sonicwall-ABCDEF123456-1999123125959.txt