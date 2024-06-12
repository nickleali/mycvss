# basic function to return a numeric score based on a CVSS metric string from vectors in a file

from cvss4py import score_vector, vector_to_equivalence_class

# set the source and destination files
source_file = "v4_vectors"
destination_file = "v4_scores"

# Open the source file for reading and the destination file for writing
with open(source_file, 'r') as source, open(destination_file, 'w') as destination:
  # Loop through each line in the source file
  for line in source:
    # Read the line and remove any trailing newline character
    line = line.rstrip()
    
    myScore = score_vector(line, validate_vector=True, warn_modified=True, replace_default=True)
    
    myScore = str(myScore)
    
    destination.write(myScore + "\n")