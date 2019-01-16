# Frequently Asked Questions

## Single-threaded Python is slow. Why didn't you use (MapReduce|Splunk|Lambda|etc)?
Those are all very good options. If one of these is easily deployable within your organization, then you should consider converting the scripts. A single threaded Python approach was the lowest common denominator for most groups. All of the scripts have a main() function rather than a series of global statements so that they can be more easily portable to one the aforementioned options.

## Is this project a network scanner?
The optional zgrab scripts are the only utilities where Marinus performs scanning itself. The majority of information collected comes from data collected by third-parties such as Common Crawl, Censys, Rapid7 Open Data, VirusTotal, etc. Marinus is not intended to replace any network security scanner.

## Does Marinus have a defined coding standard?
Marinus uses standard lint tools, such as pyLint. There is some older code within Marinus that is not 100% clean according according to these tools. The Marinus project is slowly converting the code to be compatible as updates are made.

## Will Marinus support additional services such as Shodan, Google Compute, etc.?
The Marinus project is continually adding new data sources.

## Do the third-parties formally support the Marinus project?
There are no formal relationships between the third-parties and the Marinus project.

## Why doesn't Marinus have alerting, events, etc.?
In theory, Marinus could do all of those things. When it comes to features such as alerts, everyone has different approaches (email, Slack, etc). Rather than support all of the code necessary for every possible alerting design, Marinus focuses on providing APIs for organizations to implement their own alerting according to their needs. Good apps remain focused on their core offering. Marinus' core mission is to be a database of information with an HTTPS API front end to the data.
