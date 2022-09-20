# Custom DNS resolver implementation 

## Code dependencies
- Python 3.9
- Install packages `dnspython` and `cryptography`
- NOTE: `wolfienet-secure` network does not let us connect to root servers (required for both part A and part B). So, we have to use `wolfienet-guest` or some other VPN. I have used `wolfienet-guest` for my experiments. 
## Directory structure
```
Aggarwal-Tanvi-HW1.zip
|__Aggarwal-Tanvi-HW1
    |__data.py                        (utility - datatypes and constants)
    |__experiment_part_c.pdf          (experiments and results for Part C)
    |__mydig.py                       (implementation for Part A DNS resolver mydig)
    |__mydig_output.txt               (mydig output for different cases)
    |__mydnssec.py                    (implementation for Part B DNSSec on top of mydig)
    |__mydnssec_implementation.txt    (implementation details and output for Part B)
    |__README.md                      (this file - instructions on installation and execution of code)
```
## Part A
- `mydig.py` contains the implementation for custom DNS resolver (mydig). 
- It can be used as: `python mydig.py <domain> <record type>`, e.g. `python mydig.py google.com A`.
- `mydig_output.txt` contains the output for various cases.
## Part B
- `mydnssec.py` contains the implementation for DNSSec on top of mydig. 
- It can be used as: `python mydnssec.py <domain> <record type>`, e.g. `python mydnssec.py verisigninc.com A`.
- `mydnssec_implementation.txt` contains the explanation for my implementation as well as the output for various cases.
## Part C
- `experiment_part_c.pdf` contains the experiment details, results and observations for the comparison of mydig, Local DNS and Google Public DNS resolvers.