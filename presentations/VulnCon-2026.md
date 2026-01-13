

Paths forward for CVE quality.

Reinforcing trust in CVE quality.

How can we close the vulnerability assessment gap?


#

# Closing the Vulnerability Assessment Gap

Am I affected?

And why?

These two questions flummox PSIRT teams across the industry. Technical vulnerability impacts aren't always clear, even in the best security advisories. While product vendors provide their own assessments, any number of other players in the vulnerability disclosure ecosystem make their own unique assessments and put their own spin on the issue. These additional assessments provide valuable data but can also cause confusion, leading customers to question the initial product vendor assessments.

Which assessment is correct? Is one assessment right and one wrong? Who should customers trust? How can the vulnerability disclosure ecosystem better help our customers to make decisions about prioritization?

This talk discusses pragmatic approaches to improving vulnerability assessment information for PSIRTs and the greater vulnerability disclosure ecosystem. 

First, we use public data to determine systemic issues in vulnerability assessments. The free-to-use tool will show differences in CVSS vectors for the same CVEs, analyze systemic problems in vulnerability assessment, show how PSIRT teams can use the tool to identify assessment issues in their own security advisories, and offers examples and procedures for closing that assessment gap.

Then, we propose improving CVSS and CVE documentation for helping CNAs to improve the quality of their vulnerability assessment data submissions in public vulnerability databases.

Finally, a discussion on how can all stakeholders in the vulnerability disclosure ecosystem can help to evolve actionable information in public vulnerability databases.

This talk is a companion to the submission "Words Matter: Practical Ways to Improve CVE and Advisory Quality".

## The fractured ecosystem

Data exists in many forms from many sources. The perceived unreliability, real or imagined, respresents mistrust in primary vendors. Further complicating the matter is multiple assessments performed by multiple organizations in different databases.

Scanners and other vulnerability management vendors have stepped in. 

How can we re-establish trust in primary sources? How can we help organizations manage this themselves? The first step is driving better agreement between CNAs and databases.

## Your Vendors Aren’t Lying

We look at a broad set of vendor data and examine the common types of differences seen. What kinds of issues are systemic? Is there something that the data is telling us that is common across the industry? What conclusions can be drawn about the accuracy of CVSS assessments from various sources?

Once we have identified common assessment mismatches, how can we begin to drive consistency?

This data review will demonstrate data taken from single vendors as well as broad samples to identify common assessment mismatches.

## Improving Assessment Quality

### Words Matter: Improving CVE descriptions

Transparency is important. Customers will second-guess data that isn't well explained. The description forms the basis of that trust. 

See more in the talk "Words Matter: Practical Ways to Improve CVE and Advisory Quality" and accompanying white paper.

### The CVSS Base Score problem

CVSS has become shorthand for patch prioritization. But this overstates risk. CVSS Threat and Environmental in the standard help. However, CVSS-BTE presents challenges and difficulty to do at scale.

Vector maturity.

Show in the calculator and in documentation that an assessment is incomplete until the Threat and Environmental Scores are available.

Do we need to change the conversation about who provides these assessments.

Worst-case versus reasonable deployment.

### Synthesis of existing data

How can we bring together threat intelligence, EPSS, CISA KEV, and others in a systemic way?

Can the CVE program include that data alongside CVE?

Is NVD willing to include threat and environmenta?

# Takeaways

Explain impact assessments better, restore trust in vendor-provided assessments, and ultimately aid customers in making better decisions about assets in their environments.