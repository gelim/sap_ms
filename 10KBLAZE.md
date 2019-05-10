# Some notes regarding the news release after SAP OPCDE talk

<!-- MarkdownTOC -->

- Research process and vuln disclosure
- What we pointed out
- Conditions of exploitation
    - Gateway
    - Message Server
- Incentive
- News analysis
- FUD and ethic

<!-- /MarkdownTOC -->


When reading different news report[[1]](https://www.reuters.com/article/us-sap-security/50000-companies-exposed-to-hacks-of-business-critical-sap-systems-researchers-idUSKCN1S80VJ) [[2]](https://www.computing.co.uk/ctg/news/3075298/sap-10kblaze-critical-security-flaw) [[3]](https://www.zdnet.com/article/50000-enterprise-firms-running-sap-software-vulnerable-to-attack/) on [our research presentation](https://github.com/comaeio/OPCDE/blob/master/2019/Emirates/(SAP)%20Gateway%20to%20Heaven%20-%20Dmitry%20Chastuhin%2C%20Mathieu%20Geli/(SAP)%20Gateway%20to%20Heaven.pdf) at OPCDE Dubai 2019, we had the following impression: two random hacker guys released on the darknet some 0-day targeting the world’s stability.


## Research process and vuln disclosure


We feel this is not fair as one of the implication is that it poses a threat on ourselves as security researchers, then on our actual employers that are not involved in this research, and finally on the security research process where disclosing responsibly vulnerabilities and proof of concepts is part of it. We are well known from SAP and [regularly acknowledged](https://wiki.scn.sap.com/wiki/pages/viewpage.action?pageId=451071888) for reporting security issues. We did everything according to usual guidelines on vulnerability disclosure especially with a critical vendor like SAP where there are additional safeguards to respect. Moreover SAP has had our slides beforehand and agreed on their publication.


##  What we pointed out with our research 


This research describes misuse of two misconfigurations in SAP systems core components: SAP Gateway and SAP Message Server. Those misconfigurations contains secure guidelines for several years now ([1408081](https://launchpad.support.sap.com/#/notes/1408081), [821875](https://launchpad.support.sap.com/#/notes/821875), [1421005](https://launchpad.support.sap.com/#/notes/1421005)). The highlight of our talk is based on the fact that one of the two misconfiguration is still deployed on new servers (note, that SAP explains how to harden it for a long time already). That DOES NOT directly imply the SAP servers are vulnerable to the described attack, from internet, or even from the local corporate network.


## Conditions of exploitation

### Gateway


The first old misconfiguration regarding the Gateway is the one that has nearly disappeared from our experience as SAP auditors (and confirmed by other specialists [here](https://www.serpenteq.com/en/blog/10KBlaze.html) ). The default configuration is for years secure by default. Our additional value here is to provide proof of concept open source code. About our internet world map on Gateway, it is here to show the that backend systems can be available from the internet. We noticed that most likely exposed systems where probably used for development or testing (deduction from hostname and SID when available).


### Message Server


On the second misconfiguration regarding the Message Server, several conditions need to be validated for a successful exploitation (following article https://www.serpenteq.com/en/blog/10KBlaze.html list them well). Additionally if even those conditions are presents, the attacker will have another issue: our code released is a proof of concept with a lot of wild guesses and hardcoded data. The code is far from being usable as-is as a mass attacking tool. Running this in production system may generate side-effects artifacts that will be quickly visible and won’t need security monitoring tools to get attention of administrators.


## Incentive 


Why did we release our research publicly?

SAP published for several years already hardening guides on those configuration files and associated risk. But what is the situation now? Some companies are making a big profit out of this knowledge, but global security situation does not change. SAP assets are hosting critical information. They should be the first being secured by multi layered security. With this release we want to make the difference by pointing out issues, and giving concrete example that will be directly actionable for security teams. We feel the remediation job is doable in a timely manner as those issues do not imply deploying new code. What they require instead is to know about their SAP assets.

We are assured of the benefits of spreading this knowledge in public than keeping it in the hand of some private companies after all this time since guidelines were published. We prefer to think that SAP security level just raised by having defenders knowing now what to defend for and asses their posture in an independent manner.

Moreover, we did not just released PoC, we provided improvements to the publicly accessible Python library [pysap](https://github.com/SecureAuthCorp/pysap) that helps researchers work with various protocols used in SAP.


## News analysis


The most relayed news articles do some quick shortcut that helps propagate fear: taking the number of SAP clients, taking as granted insecure configurations and that our tools are 100% reliable. They don’t go into details about conditions required for all of that to happen. Additionally there is the assumption that no one had already this knowledge nor there is any malicious actor eventually able to get this knowledge on their own.
Keeping the knowledge and exploits in-house (as Onapsis did) does not help to increase the security posture of the SAP customers but instead works on the model of "security through obscurity".

On all the articles you can find, the only news company that have been in contact with us is Reuters. Unfortunately it was not possible to know in advance details of the resulting article and our requests for clarifications and edits after publication were unsuccessful.

## FUD and ethic


The will of companies to make money combined with the desire of some journalists to write a traffic-generating article with clickbait titles leads us to the fact that every day we have to read news that the next trillion systems / devices were hacked, although in fact someone just found double-blind- self-xss (this is a fictional name) on a forgotten domain of a well-known company

In our case, everything turned out to be much worse. Onapsis did not just release a frightening press release that 9 out of 10 are vulnerable describing our research, but also came up with the name 10KBlaze (where is our logo and dedicated domain?) for our PoCs without specifying any direct links to the original research.

Those 9 out of 10 might be a wild guess from Onapsis' customer base, We are sure it does not represent the universe of all SAP customers. Onapsis' customers probably are hiring them because they need security advise and are probably not representative of the overall status of security.

A simple search on the hashtag #10KBlaze shows how much Onapsis wants the community to find out about our work, without mentioning us.


![twit](twitter.gif) 


Did they have the right to do that? Of course! Is it ethical? We do not think so.

We don't like FUD, we believe in facts. PoC or GTFO. 


Dmitry Chastuhin & Mathieu Geli 


