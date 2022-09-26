# parse_sonicwall_exp.py

Decodes and parses the provided Sonicwall exp file and exports some key information out to worksheets in an Excel Spreadsheet. 

It does not parse all the information in the exp file and should defintitely be considered a work in progress. 

Install the Python requirements with :

- pip install -r requirements.txt

Invoke the script passing the exp filename in the command line:

- ./parse_sonicwall_exp.py ./sonicwall-ABCDEF123456-19991231235959.exp  