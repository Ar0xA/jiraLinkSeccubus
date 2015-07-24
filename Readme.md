jiraLinkSeccubus is a program to create tickets from Seccubus (https://www.seccubus.com/) to Jira. 
The status of the ticket in Jira is relected in Seccubus, and the other way around.

The comment field of a finding in Seccubus is used to store data that is required to link with Jira. EDIT BY HAND AT YOUR OWN PERIL!

All code of this project is covered under GPL 2 as can be found in the LICENSE file.

Copyright (c) 2015 by Ar0xA

**Quickstart**

0. Have a system with Python 3
1. fill in the information required to connect in the jiraLinkSeccubusSettings.json file.
2. have both the python and json file in a location that reach both the Seccubus webinterface and the jira api.
3. Run jiraLinkSeccubus without any parameters for a quick help.
4. Run the application with --spaces=all, --spaces=[id] or --spaces=[id1],[id2],etc.

NOTE 1:  The setting alwaysMakeJiraLink True will always create a Jira ticket, even if tickets do NOT have NEW status. Otherwise only tickets in jira will be created if the status in Seccubus is "NEW".

NOTE 2: I am not a programmer. I made this because I needed it. If my code sucks, if my comments suck. Feel free to issue a pull request and fix my crap code :)

**TODO**
- Include Seccubus findingID, workspace and scanname in the json to Jira
- use a local database instead of Seccubus comments to keep track of the link between Seccubus and Jira
