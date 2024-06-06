# quick and dirty conversion from v3.1 to v4.0 score

# read string from file and modify to 4

# set the source and destination files
source_file = "v3_vectors"
destination_file = "v4_vectors"

# Open the source file for reading and the destination file for writing
with open(source_file, 'r') as source, open(destination_file, 'w') as destination:
  # Loop through each line in the source file
  for line in source:
    # Read the line and remove any trailing newline character
    line = line.rstrip()
    
    '''
    The checks we need to perform to translate v3 to v4 scores:
    Attack Vector -- directly translate
    Attack Requirements -- If AC:H, then set AT:P 
    User Interaction -- If UI:R, then set UI:P
    Privileges Required -- directly translate
    Scope -- Ignore for now
    Impact Metrics -- Convert CIA to VC / VI / VA, ignore subsystem    
    
    '''
    
    # if scope exists, throw it out
    
    if "S:U" in line:
    # proceed with processing since we don't have a scope change
      # attack vector checks
      if "AV:N" in line:
        v4_string = "CVSS:4.0/AV:N"
      elif "AV:A" in line: 
        v4_string = "CVSS:4.0/AV:A"
      elif "AV:L" in line:
        v4_string = "CVSS:4.0/AV:L"
      else: 
        v4_string = "CVSS:4.0/AV:P"

      # attack complexity checks
      if "AC:L" in line:
        v4_string = v4_string + "/AC:L/AT:N"
      else:
        v4_string = v4_string + "/AC:L/AT:P"

      # privileges required checks
      if "PR:N" in line:
        v4_string = v4_string + "/PR:N"
      elif "PR:L" in line:
        v4_string = v4_string + "/PR:L"
      else:
        v4_string = v4_string + "/PR:H"

      # user interaction checks
      if "UI:R" in line:
        v4_string = v4_string + "/UI:P"
      else:
        v4_string = v4_string + "/UI:N"

      # confidentliaty impact metric processing
      if "/C:N" in line:
        v4_string = v4_string + "/VC:N"
      elif "/C:L" in line:
        v4_string = v4_string + "/VC:L"
      else:
        v4_string = v4_string + "/VC:H"

      # integrity impact metric processing
      if "/I:N" in line:
        v4_string = v4_string + "/VI:N"
      elif "/I:L" in line:
        v4_string = v4_string + "/VI:L"
      else:
        v4_string = v4_string + "/VI:H"

      if "/A:N" in line:
        v4_string = v4_string + "/VA:N"
      elif "/A:L" in line:
        v4_string = v4_string + "/VA:L"
      else:
        v4_string = v4_string + "/VA:H"

      # we don't care about subsystem impacts, so make it simple and add on NNN
      
      v4_string = v4_string + "/SC:N/SI:N/SA:N"
      
      # output the derived score in v4_string
      
      print(v4_string)
      
    else:
      print("Scope detected, skipping.")

    # combine the final vector string with the derived v4_string for the later v4 score check

    url = "https://www.first.org/cvss/calculator/4.0#" + v4_string
      
    # call the web scraper and get the value back
    # do this later
     
    # calc_value = get_score(url)
      
    # Write the vector and score to the destination file
    # destination.write(calc_value + " " + line + "\n")
    # destination.write(line + "\n")
    # print(line)
    # print(v4_string)
