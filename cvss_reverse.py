# A simple script with documented rules to generate a CVSS v3.1 vector string if a CVSS v4.0 is supplied.

def count_impact_metrics(vector, metrics):
    """
    Checks a supplied CVSS vector for the presence of the supplied metrics.

    Args:
        vector: the CVSS vector string
        metrics: the desired metrics to check
    """
    counts = 0

    for metric in metrics:
        counts = counts + vector.count(metric)
    return counts



# set the source and destination files
source_file = "v4_vectors"
destination_file = "v3_vectors"

# defining vulnerable and subsequent system dictionaries for later comparison

vulnSystemImpacts = ["VC:H", "VI:H", "VA:H"]

subsSystemImpacts = ["SC:H", "SI:H", "SA:H"]

# Open the source file for reading and the destination file for writing
with open(source_file, 'r') as source, open(destination_file, 'w') as destination:
  # Loop through each line in the source file
  for line in source:
    # Read the line and remove any trailing newline character
    line = line.rstrip()
    
    '''
    The checks we need to perform to work backwards from a v4.0 vector to get a v3.1 vector:
    Attack Vector -- directly translate to v3.1
    Attack Requirements -- If AC:H or AT:P, then set AC:H.
    User Interaction -- If UI:P or UI:A, then set UI:R
    Privileges Required -- also directly translate
    Scope -- A little tricky. Basically, we need to see if either CIA or vulnerable or subsequent system has non-N metrics. 
        If there are more H values for one than the other, use that as the vector.
    Impact Metrics -- In the event of two sets, pick the highest. Convert CIA to C / I / A.

    Exploit maturity -- This is harder. We can make a rule that High means Attacked. Does Functional also equal Attacked?
        PoC maps to v3.1. Unproven is also the same.
    
    '''
       
    # attack vector checks
    if "AV:N" in line:
        v3_string = "CVSS:3.1/AV:N"
    elif "AV:A" in line: 
        v3_string = "CVSS:3.1/AV:A"
    elif "AV:L" in line:
        v3_string = "CVSS:3.1/AV:L"
    else: 
        v3_string = "CVSS:3.1/AV:P"

    # attack complexity checks
    if "AT:P" in line:
        v3_string = v3_string + "/AC:H"
    elif "AC:H"  in line:
        v3_string = v3_string + "/AC:H"
    else:
        v3_string = v3_string + "/AC:L"

      # privileges required checks
    if "PR:N" in line:
        v3_string = v3_string + "/PR:N"
    elif "PR:L" in line:
        v3_string = v3_string + "/PR:L"
    else:
        v3_string = v3_string + "/PR:H"

      # user interaction checks
    if "UI:P" in line:
        v3_string = v3_string + "/UI:R"
    elif "UI:A" in line:
        v3_string = v3_string + "/PR:L"
    else:
        v3_string = v3_string + "/UI:N"

    # confidentliaty impact metric processing
    # need some better logic and loops for checking for scope changes

    scopeCheckList = ["SC:L", "SC:H", "SI:L", "SI:H", "SA:L", "SA:H"]
    # check v4.0 string for subsequent system impacts and if so, set scope change in v3.1 vector string

    if any(x in line for x in scopeCheckList):
        v3_string = v3_string + "/S:C"
    else:
        v3_string = v3_string + "/S:U"

    # how can we smartly recreate the impacts?
    # Code block here to set the system impact metrics based on those in the either the vulnerable or subsequent system.
    # Adapt if it's a higher value on the vulnerable versus subsequent system, and use the higher. 

    # get count of H in either r"SC|SI|SA:L|H" and use which has more H
    # if they are the same, how do we reconcile

    if count_impact_metrics(line, vulnSystemImpacts) > count_impact_metrics(line, subsSystemImpacts):
        if "/VC:N" in line:
            v3_string = v3_string + "/C:N"
        elif "/VC:L" in line:
            v3_string = v3_string + "/C:L"
        else:
            v3_string = v3_string + "/C:H"

        # integrity impact metric processing
        if "/VI:N" in line:
            v3_string = v3_string + "/I:N"
        elif "/VI:L" in line:
            v3_string = v3_string + "/I:L"
        else:
            v3_string = v3_string + "/I:H"

        if "/VA:N" in line:
            v3_string = v3_string + "/A:N"
        elif "/VA:L" in line:
            v3_string = v3_string + "/A:L"
        else:
            v3_string = v3_string + "/A:H"
    else:
        if "/SC:N" in line:
            v3_string = v3_string + "/C:N"
        elif "/SC:L" in line:
            v3_string = v3_string + "/C:L"
        else:
            v3_string = v3_string + "/C:H"

        # integrity impact metric processing
        if "/SI:N" in line:
            v3_string = v3_string + "/I:N"
        elif "/SI:L" in line:
            v3_string = v3_string + "/I:L"
        else:
            v3_string = v3_string + "/I:H"

        if "/SA:N" in line:
            v3_string = v3_string + "/A:N"
        elif "/SA:L" in line:
            v3_string = v3_string + "/A:L"
        else:
            v3_string = v3_string + "/A:H"
    
    # handling threat

    try:
        if "E:A" in line:
            v3_string = v3_string + "/E:H"
        elif "E:P" in line:
            v3_string = v3_string + "/E:P"
        else:
            v3_string = v3_string + "/E:X"
    except:
        pass

    # output the derived score in v3_string
      
    print(v3_string)

    # combine the final vector string with the derived v3_string for the later v4 score check

    url = "https://www.first.org/cvss/calculator/3.1#" + v3_string
           
    # Write the vector and score to the destination file
    # destination.write(calc_value + " " + line + "\n")
    destination.write(v3_string + "\n")
    # print(line)
    # print(v3_string)

