# Closing the Vulnerability Assessment Gap

Closing the Vulnerability Assessment Gap: Identifying Discrepancies in Vulnerability Assessments and Restoring Trust in the Vulnerability Disclosure Ecosystem

Am I affected?

And why?

These two questions flummox PSIRT teams across the industry. Technical vulnerability impacts aren't always clear, even in the best security advisories. While product vendors provide their own assessments, any number of other players in the vulnerability disclosure ecosystem make their own unique assessments and put their own spin on the issue. These additional assessments provide valuable data but can also cause confusion, leading customers to question the initial product vendor assessments.

Which assessment is correct? Is one assessment right and one wrong? Who should customers trust? 

This talk will attempt to use public data to determine systemic issues in vulnerability assessments. The free-to-use tool will show differences in CVSS vectors for the same CVEs, analyze systemic problems in vulnerability assessment, show how PSIRT teams can use the tool to identify assessment issues in their own security advisories, and offers examples and procedures for closing that assessment gap.

As a call to action, the talk will solicit feedback on how we in the CVSS SIG specifically, and FIRST in general, can improve the fidelity of and trust in vulnerability assessment data in public vulnerability databases.

This talk is a companion to Improving Human-Readable Vulnerability Descriptions.

## The Tool

Introducing the CVSS Verifier, a containerized dashboard for identifying differences between your own provided CVSS assessments and those from NVD and other sources.

## Data Review

Using the CVSS Assessment Verifier, look at a broad set of vendor data and examine the common types of differences seen.

What kinds of issues are systemic? Is there something that the data is telling us that is common across the industry? What conclusions can be drawn about the accuracy of CVSS assessments from various sources?

This data review will demonstrate data taken from single vendors as well as broad samples to identify common assessment mismatches.

## Corrective Actions

Once we have identified common assessment mismatches, how can we begin to drive consistency?

The goal is to explain impact assessments better, restore trust in vendor-provided assessments, and ultimately aid customers in making better decisions about assets in their environments.

A number of proposals are offered.

### Use Tooling to Identify Outliers

First, use the proposed tool or other to verify CVSS assessments and identify scores that may be in error in your own environment. Once those are understood, adopt process improvements or training as described in the following points to improve assessments or describe them more transparently. 

### Natural Language Descriptions

Proper descriptions and clear language lead to transparency of vulnerability assessmnets. 

To that end, improve natural language descriptiveness of vulnerability assessments. Language must be specific and agree with the CVSS vector and other assessment metrics. Reference a whitepaper currently in progress around improving vulnerability descriptions and how to drive better agreement with third-party vulnerability assessment through language transparency. 

### CVSS Scoring Rubric

Are the differences in assessments not a language transparency problem, but instead a process issue? Is the CVSS standard applied incorrectly, or a documentation issue, that the standard is unclear?

Refer to the CVSS Specification Document and User Guide. Include those in PSIRT incident manager training and references.

If those are not descriptive enough, how can the CVSS SIG help to improve? 

Mulitiple approaches to improving the CVSS specification document in the CVSS v4.0 revision.

### CVSS Examples

A number of examples of common vulnerability types exist in the CVSS Examples documentation.

How can the CVSS SIG improve clarity of and expand on examples, including those using Threat and Environmental metrics?