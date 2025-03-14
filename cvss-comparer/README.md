Start of the CVSS Comparer.

This tool will check (at first the CVE Program) data sources for CVSS vector scores and do some mathematical analysis on them, determining changes between v3.1 and v4.0 scores.

# Tool features

The tool can run in directory scan or single CSV scan mode. Set those file paths and modes in the source.

Once run, there are a number of outputs that can be generated. See more about the methodologies behind those outputs below.

## Outputs

### All Data

The tool can output a (often concatenated) display of the stored array of v3 and v4 scores.
print("Press the d key for all the raw data found.")

### Total records

The tool ouputs a count of all the found score pairs.
print("Press the t key for a total number of compared records.")

### Average
print("Press the a key for the average of the differences.")

### Mode

The tool shows the mode for the set, as in, the most common changed value between CVSS v3.1 and v4.0 scores.
print("Press the m key for the mode of the differences.")

### Range

This can be a little misleading, but the tool outputs the total range, the span of values, between the largest increased and decreased value of the data set. Need to work on clarifying this a little bit! In some of the data there are weird outliers. 

print("Press the r key for the range of the differences.")

### Boundary Changes

The tool does a count of all scores that change qualitative boundary changes between v3.1 and v4.0 scores.

print("Press the 3 key to list boundary changes between found v3.1 and v4.0 scores.")

### Graphs

There are a number of graph outputs the tool can generate. 

First, it can show all the found v3.1 and v4.0 scores.

print("Press the l key to generate a graph of all found CVSS scores.")

Then, it can generate a histogram of the differences betwen all found CVSS scores pairs.

print("Press the h key for a histogram of the found differences between the found CVSS scores.")

Finally, the tool can show the set of v4.0 scores, and then automatically enrich those scores with threat and environmental metrics.

print("Enter c for a graph of CVSS-B scores matched with modified v4.0 scores compared with the KEV.")

# Methodology

## Direct comparison

Show the difference between the scores.

## Counts

Raw score counts, ie, how many numbers appear.

The mean, median, and mode of the entire set, broken out by version, v3.1 and v4.0.

## Average Distance

The overall average change between v3.1 and v4.0.

## Range Distance

The overall distance of changes, ie, the perceived inaccuracy.

# Possible vector enrichment

Check the CVEs for KEV, and modify other environmental variables.