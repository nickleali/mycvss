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
    Impact Metrics -- In the event of two sets, pick the highest. Convert CIA to C / I / A. 
        If there are more H values for one than the other, use that as the vector.
        If the vectors match, or have the count of High impacts, use the vulnerable system for the CIA score in v3.1.
        In either case, if there are subsequent system impacts, set Scope to Changed.

    Exploit maturity -- High equates to Attacked, roughly. Setting Functional to Attacked as well.
        PoC maps to v3.1. Unproven is also the same.
    
    '''
       
    # Check each vector string for Attack Vector values and set the v3.1 value accordingly
    if "AV:N" in line:
        v3_string = "CVSS:3.1/AV:N"
    elif "AV:A" in line: 
        v3_string = "CVSS:3.1/AV:A"
    elif "AV:L" in line:
        v3_string = "CVSS:3.1/AV:L"
    elif "AV:P" in line:
        v3_string = "CVSS:3.1/AV:P"
    else:
        v3_string = "CVSS:3.1/AV:N"

    # Checks for Attack Complexity 
    if "AT:P" in line:
        v3_string = v3_string + "/AC:H"
    elif "AC:H"  in line:
        v3_string = v3_string + "/AC:H"
    else:
        v3_string = v3_string + "/AC:L"

    # Checks for Privileges Required
    if "PR:N" in line:
        v3_string = v3_string + "/PR:N"
    elif "PR:L" in line:
        v3_string = v3_string + "/PR:L"
    elif "PR:H" in line:
        v3_string = v3_string + "/PR:H"
    else:
        v3_string = v3_string + "/PR:N"

      # Checks for User Interaction
    if "UI:P" in line:
        v3_string = v3_string + "/UI:R"
    elif "UI:A" in line:
        v3_string = v3_string + "/PR:L"
    else:
        v3_string = v3_string + "/UI:N"

    scopeCheckList = ["SC:L", "SC:H", "SI:L", "SI:H", "SA:L", "SA:H"]
    
    # Ensure that per the CVSS v3.1 standard, any CVSS v4.0 vector strings that have subsequent system impacts should also 
    # be set to 'Scope:Changed' in the v3.1 vector string, even if the vulnerable system impacts are used. 
    # See v3.1 scoring rubric for scope chance in v3.1 Spec Doc section 2.3: 
    # https://www.first.org/cvss/v3.1/specification-document#2-3-Impact-Metrics

    if any(x in line for x in scopeCheckList):
        v3_string = v3_string + "/S:C"
    else:
        v3_string = v3_string + "/S:U"

    # Below code block sets the system impact metrics based on those in the either the vulnerable or subsequent system.
    # Adapt if it's a higher value on the vulnerable versus subsequent system, and use the higher. 

    # get count of H in either r"SC|SI|SA:L|H" and use which has more H
    # if they are the same, how do we reconcile

    if count_impact_metrics(line, vulnSystemImpacts) >= count_impact_metrics(line, subsSystemImpacts):
        # vulnerable system Confidentiality impact metric processing
        if "/VC:N" in line:
            v3_string = v3_string + "/C:N"
        elif "/VC:L" in line:
            v3_string = v3_string + "/C:L"
        else:
            v3_string = v3_string + "/C:H"

        # vulnerable system Integrtity impact metric processing
        if "/VI:N" in line:
            v3_string = v3_string + "/I:N"
        elif "/VI:L" in line:
            v3_string = v3_string + "/I:L"
        else:
            v3_string = v3_string + "/I:H"

        # vulnerable system Availability impact metric processing
        if "/VA:N" in line:
            v3_string = v3_string + "/A:N"
        elif "/VA:L" in line:
            v3_string = v3_string + "/A:L"
        else:
            v3_string = v3_string + "/A:H"
    else:
        # subsequent system Confidentiality impact metric processing
        if "/SC:N" in line:
            v3_string = v3_string + "/C:N"
        elif "/SC:L" in line:
            v3_string = v3_string + "/C:L"
        else:
            v3_string = v3_string + "/C:H"

        # subsequent system Integrity impact metric processing
        if "/SI:N" in line:
            v3_string = v3_string + "/I:N"
        elif "/SI:L" in line:
            v3_string = v3_string + "/I:L"
        else:
            v3_string = v3_string + "/I:H"

        # subsequent system Availability impact metric processing
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
        elif "E:X" in line:
            v3_string = v3_string + "/E:X"
        else:
            v3_string = v3_string + "/E:X"
    except:
        pass

    # output the derived score in v3_string
      
    print(v3_string)

    # combine the final vector string with the calculator URL if we want to supply that

    url = "https://www.first.org/cvss/calculator/3.1#" + v3_string
           
    # Write the vector and score to the destination file
    # destination.write(calc_value + " " + line + "\n")
    destination.write(v3_string + "\n")

    # end of file check loop

# end of program


