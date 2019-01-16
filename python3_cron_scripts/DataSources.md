# Understanding Data Sources

There are several things that can affect the data that is retrieved from third-party data sources. This page tries to summarize some of the trends that you may see in the data that you collect.

## Variability
Each data source has its own methods for collecting data and different types of variability in their results. Sometimes the change in results is expected as part of the normal lifespan of a resource. For instance, a host may have intentionally been taken offline or migrated causing it to no longer show up in the third-party results. However, there can be additional reasons for variability in the data.

When performing over a billion network requests, the chances of an individual request failing is greater than zero. This will mean that a record may be in data set 1, missing in data set 2, and then reappear in data set 3. Therefore, Marinus expires most records after a two-month period in order to account for the possibility that a network error caused a record to be missing from any single data set. A two-month period ensures that the scripts have had multiple chances to execute before permanently removing the record.

DNS load balancing can also result in variability within the data set. With DNS load balancing, a lookup for www.example.org may result in the address 1.2.3.4. The next DNS lookup might return the address 1.2.3.5. Unless someone repeatedly queries for www.example.org, they may only see a subset of the possible addresses that are valid for that domain.

The methodology of third-party provider may also change over time resulting in different data sets. As an example, the Common Crawl graph data for the months of May/June/July 2018 was 5.6GB. The size of graph data for the prior quarter (Feb/Mar/Apr 2018) was 12.45 GB. The quarter prior to that was 15.9GB. The Common Crawl methodology does not produce the exact same output from quarter to quarter. As remote data sources shift their techniques and targets, the resulting data that is collected will also shift. Therefore, when first starting out with Marinus and Common Crawl, there may be value in using previous data sets in addition to the most recent data set.

## Time delays
Marinus does not provide real-time DNS results. For third-party data sources, it is important to keep in mind the lifecycle of the data. The third-party will run their scans which typically takes some time on their end. They then have to package and upload the data to make it available to the public. Finally, Marinus has to download and parse the data which can take time. Therefore, the time between when the data was collected by the third-party and when Marinus inserts it into the database may vary. Depending on the how frequently the third-party updates, it could be days or weeks between the measurement of the data and when it shows up in Marinus results. Therefore, the Marinus data set should not be considered to be real time results. That does not mean that the data is not valuable. Chances are that your company doesn't overhaul its entire infrastructure on a daily basis. It just means that care should be applied when you use the data for network scans or other scenarios where a stale record could cause unintentional damage.

## Number of data sources
Within Adobe's use of Marinus, the vast majority of records come from a single data source. In terms of a Venn diagram, there is very little overlap between the various sources. The overlap that does occur between data sources tends to be for the obvious records (e.g. www.example.org). Therefore, Marinus supports multiple data sources because no single data source can be considered robust enough to be fully representative of our networks. The quality of Marinus data increases with each new data source.

## Certificate transparency logs
There are multiple CT log servers and they change every year. An individual CT log server is not guaranteed to host all known certificates. Typically, a CT Log server will primarily host the certificates that are associated with the server operator. For instance, a DigiCert CT Log server will primarily host Digicert issued certificates. Therefore, it is important to understand who issues the certificates for your organization to ensure that you search the correct log servers.

Several of the Google CT log servers tend to be used as the secondary log servers by the major CAs. Therefore, they are often good for general searches. The Facebook Graph API searches across all CT Log servers but you must be a Facebook customer in order to use their services.

Most certificates will have the details of which CT Log servers that they are registered with embedded within the certificate. Therefore, if you are collecting TLS certificates through another method, such as zgrab scans, then you can look inside of them to determine where they are registered and use that to decide which CT log servers to query more deeply with Marinus.

Keep in mind that if you use a third-party CDN, then they may be creating TLS certificates for your domain through their own CAs. This can sometimes cause confusion when first viewing the list of certificate authorities that Marinus identifies. If you want to search for rogue certificates from compromised CAs, then you first need to review all the CDNs and partners who may legitimately be issuing certificates for your domain.
