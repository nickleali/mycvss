import itertools
import time

baseAndThreatMetrics = [
    # Base (11 metrics)
    ["CVSS:4.0/AV:N/", "CVSS:4.0/AV:A/", "CVSS:4.0/AV:L/", "CVSS:4.0/AV:P/"],
    ["AC:L/", "AC:H/"],
    ["AT:N/", "AT:P/"],
    ["PR:N/", "PR:L/", "PR:H/"],
    ["UI:N/", "UI:P/", "UI:A/"],
    ["VC:H/", "VC:L/", "VC:N/"],
    ["VI:H/", "VI:L/", "VI:N/"],
    ["VA:H/", "VA:L/", "VA:N/"],
    ["SC:H/", "SC:L/", "SC:N/"],
    ["SI:H/", "SI:L/", "SI:N/"],
    ["SA:H/", "SA:L/", "SA:N/"],
    # Threat (1 metric)
    ["E:X/", "E:A/", "E:P/", "E:U/"],
]
environmentalMetrics = [
    # Environmental (14 metrics)
    ["CR:X/", "CR:H/", "CR:M/", "CR:L/"],
    ["IR:X/", "IR:H/", "IR:M/", "IR:L/"],
    ["AR:X/", "AR:H/", "AR:M/", "AR:L/"],
    ["MAV:X/", "MAV:N/", "MAV:A/", "MAV:L/", "MAV:P/"],
    ["MAC:X/", "MAC:L/", "MAC:H/"],
    ["MAT:X/", "MAT:N/", "MAT:P/"],
    ["MPR:X/", "MPR:N/", "MPR:L/", "MPR:H/"],
    ["MUI:X/", "MUI:N/", "MUI:P/", "MUI:A/"],
    ["MVC:X/", "MVC:H/", "MVC:L/", "MVC:N/"],
    ["MVI:X/", "MVI:H/", "MVI:L/", "MVI:N/"],
    ["MVA:X/", "MVA:H/", "MVA:L/", "MVA:N/"],
    ["MSC:X/", "MSC:H/", "MSC:L/", "MSC:N/"],
    ["MSI:X/", "MSI:S/", "MSI:H/", "MSI:L/", "MSI:N/"],
    ["MSA:X/", "MSA:S/", "MSA:H/", "MSA:L/", "MSA:N/"],
    # Supplemental (6 metrics), unused for scoring, but uncomment to check
    # ["S:X/", "S:N/", "S:P/"],
    # ["AU:X/", "AU:N/", "AU:Y/"],
    # ["R:X/", "R:A/", "R:U/", "R:I/"],
    # ["V:X/", "V:D/", "V:C/"],
    # ["RE:X/", "RE:L/", "RE:M/", "RE:H/"],
    # ["U:X", "U:Clear/", "U:Green/", "U:Amber/", "U:Red/"],
]

# iterate the space and print the results

for element in itertools.product(*baseAndThreatMetrics):
	str = ''
	for item in element:
		str = str + item
	print(str)
	# time.sleep(1)
	# get mav to msa values
	for x in range(0, 14):
		currMetric = environmentalMetrics[x]
		# print(currMetric)
		# Trying to iterate through all strings and then replace the modified value
		for currThing in currMetric:
			#print("hello?")
			#get current vulnerability type
			currSubstring = currThing[1:3]
			#print("This is the current substring selected: " + currSubstring)
			#print(currSubstring)
			#find current vulnerability type an match unique base case to it
			match currSubstring: 
				case "AV":
					print(str + currThing)
				case "AC":
					print(str + currThing)
				case "PR":
					print(str + currThing)
				case "UI":
					print(str + currThing)
				case "VC":
					print(str + currThing)
				case "VI":
					print(str + currThing)
				case "VA":
					print(str + currThing)
	
			
			
	

