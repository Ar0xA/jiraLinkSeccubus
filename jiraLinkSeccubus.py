#jiraLinkSeccubus, Copyright (C) 2015 Ar0xA
#
#jiraLinkSeccubus comes with ABSOLUTELY NO WARRANTY;
#This is free software, and you are welcome
#to redistribute it under certain conditions; see
#attached LICENSE file for details.


import json
import sys
import requests
import re
import ast
from requests.auth import HTTPBasicAuth

# disable warnings about ssl certs..yes we know!
requests.packages.urllib3.disable_warnings()

# this will contain the global settings data from the .json settings file
SETTINGS = ""

# do you like logging? this is how you get logging
# True/False
VERBOSE = True


def getScans(workspaceId):
    # Here we get the list of scans for a specific workspace. This returns the
    # ID's and names of the scans.
    try:
        # build the URL from the settings
        getScansURL = SETTINGS['Seccubus'][
            'seccubusServer'] + SETTINGS['Seccubus']['getScansUrl']
        # get user/password from settings
        user = SETTINGS['Seccubus']['seccubusUser']
        password = SETTINGS['Seccubus']['seccubusPassword']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    payload = "workspaceId=" + workspaceId
    print("* Requesting scans for workspace: %s" % workspaceId)
    try:
        r = requests.post(
            getScansURL,
            auth=HTTPBasicAuth(
                user,
                password),
            data=payload,
            verify=False)
        result = r.json()

        # from seccubus; if the response is 200, it can still contain "error"
        print ("* There are %i scans for this workspace." % len(result))
        scanIds = []
        for stuff in result:
            scanIds.append((stuff.get('id'), stuff.get('name')))
        return scanIds
    except:
        print(
            "Error requesting scans from Seccubus for workspace. Error: ",
            sys.exc_info())
        exit(1)


def getLastRun(workspaceId, scanId):
    # get the last run scan information
    try:
        # build getFindingsURL from SETTINGS
        getRunsURL = SETTINGS['Seccubus'][
            'seccubusServer'] + SETTINGS['Seccubus']['getRunsUrl']
        # get user/password from settings
        seccubusUser = SETTINGS['Seccubus']['seccubusUser']
        seccubusPassword = SETTINGS['Seccubus']['seccubusPassword']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    payload = "workspaceId=" + workspaceId + "&scanId=" + scanId[0]
    try:
        r = requests.post(
            getRunsURL,
            auth=HTTPBasicAuth(
                seccubusUser,
                seccubusPassword),
            data=payload,
            verify=False)
        result = r.json()
        return result[0]
    except:
        print("Error getting last run from Seccubus. Error: ", sys.exc_info())
        exit(1)


def getFindings(workspace, scanIddict, status):
    try:
        # build getFindingsURL from SETTINGS
        getFindingsURL = SETTINGS['Seccubus'][
            'seccubusServer'] + SETTINGS['Seccubus']['getFindingsUrl']
        # get user/password from settings
        seccubusUser = SETTINGS['Seccubus']['seccubusUser']
        seccubusPassword = SETTINGS['Seccubus']['seccubusPassword']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    scanId = scanIddict[0]
    scanName = scanIddict[1]
    # status:1 == New, 2 == changed, 3 == open
    payload = "workspaceId=" + workspace + "&scanIds%5B%5D=" + scanId + "&Status=" + \
        str(status) + "&Scans%5B%5D=" + scanId + "&Host=*&HostName=*&Port=*&Plugin=*&Severity=*&Finding=*&Remark=*"
    try:
        r = requests.post(
            getFindingsURL,
            auth=HTTPBasicAuth(
                seccubusUser,
                seccubusPassword),
            data=payload,
            verify=False)
        result = r.json()
    except:
        print(
            "Error requesting scans from Seccubus for workspace. Error: ",
            sys.exc_info())
        exit(1)
    scanResults = []
    for items in result:
        scanResults.append(
            (items.get('host'),
             items.get('hostName'),
             items.get('severityName'),
             items.get('port'),
             items.get('find'),
             items.get('remark'),
             items.get('plugin'),
             items.get('id')))
    return scanResults


def formatNewFinding(findInfo, workspace, status):
    try:
        # build severityTicketMatch from SETTINGS
        severityTicketMatch = SETTINGS['General']['severityTicketMatch']
        remarkTXT = SETTINGS['General']['remarkTxt']
        jiraSeverityMapping = ast.literal_eval(
            SETTINGS['Jira']['jiraSeverityMapping'])
        jiraProjectKey = SETTINGS['Jira']['jiraProjectKey']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    jiraCreateTicketJSON = """
{
    "fields": {
       "project":
       {
          "key": "%s"
       },
       "summary": "%s",
       "description": "%s",
           "priority": {
              "name": "%s"
           },
           "environment": "%s",
       "issuetype": {
          "name": "Task"
       }
   }
}"""
    # now we only want those that are above the treshhold
    if (findInfo[2] in severityTicketMatch) and (
            findInfo[5] == None or findInfo[5].find(remarkTXT) < 0):
        print(
            "\t\tFinding is above severity treshhold, and remark field does not contain string, lets create a ticket!")
        # map Severity to Jira
        severity = jiraSeverityMapping.get(findInfo[2])
        url = findInfo[1]  # hostname can be empty
        if url is None:
            url = ""
        ipaddr = findInfo[0]
        port = findInfo[3]
        # fix formatting of the Nessus finding field, so it renders correctly
        # in Jira
        description = findInfo[4].replace("\\", "\\\\")
        description = description.replace("\n", "\\n")
        description = description.replace('"', '\\"')
        pluginID = findInfo[5]

        # get part of the info from the first line... to have in the summary
        firstlineFind = findInfo[4][0:findInfo[4].find("\n")]
        summary = ipaddr + " (" + url + ") - " + firstlineFind
        if len(summary) > 254:
            summary = summary[0:254]
        environment = ipaddr + " (" + url + ")"
        # TODO: add scan date to the findings!
        jiraTicket = jiraCreateTicketJSON % (
            jiraProjectKey, summary, description, severity, environment)
        return jiraTicket


def doJiraPost(overrideURL, Data, protocol):
    try:
        jiraUser = SETTINGS['Jira']['jiraUser']
        jiraPassword = SETTINGS['Jira']['jiraPassword']
        jiraURL = SETTINGS['Jira']['jiraApiUrl']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    # we want to be able to pass a custom URL, to update issues, etc
    if not overrideURL is None:
        jiraURL = overrideURL
    try:
        headers = {
            'User-Agent': 'Seccubus2Jira 1.0',
            'Content-Type': 'application/json'}
        if protocol == 'POST':
            r = requests.post(
                jiraURL,
                auth=HTTPBasicAuth(
                    jiraUser,
                    jiraPassword),
                data=Data,
                headers=headers,
                verify=False)
        elif protocol == 'GET':
            r = requests.get(
                jiraURL,
                auth=HTTPBasicAuth(
                    jiraUser,
                    jiraPassword),
                headers=headers,
                verify=False)
        else:
            print('Protocol error, not POST or GET')
            exit(1)
        return r
    except:
        print("Error Posting data to Jira. Error: ", sys.exc_info())
        exit(1)


def createTicket(JsonData):
    # here we fill the json to submit to Jira and create the ticket
    result = doJiraPost(None, JsonData.replace('\n', ''), 'POST')
    if result.status_code == 201:
        result = result.json()
        print (
            ("\t\tticket ID: %s Name: %s created in Jira") %
            (result.get('id'), result.get('key')))
        return result
    else:
        print ("** Error creating ticket in Jira")
        print (result.status_code)
        print (result.text)
        exit(1)


def updateSeccubusAfterCreate(jiraTicketInfo, findInfo, status, workspace):
    # with the returned information, we update Seccubus
    try:
        # build getFindingsURL from SETTINGS
        updateFindingsURL = SETTINGS['Seccubus'][
            'seccubusServer'] + SETTINGS['Seccubus']['updateFindingsUrl']
        # get user/password from settings
        seccubusUser = SETTINGS['Seccubus']['seccubusUser']
        seccubusPassword = SETTINGS['Seccubus']['seccubusPassword']
        remarkTXT = SETTINGS['General']['remarkTxt']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    try:
        # using the ticketID (findInfo[7]), we update the finding with the jira
        # text, ID
        updateText = remarkTXT + "TicketID: " + \
            jiraTicketInfo.get('id') + "\nKey: " + jiraTicketInfo.get('key') + "\n"
        payload = "ids%5B%5D=" + findInfo[7] + "&attrs%5Bremark%5D=" + updateText + \
            "&attrs%5Bstatus%5D=" + str(status) + "&attrs%5BworkspaceId%5D=" + workspace
        r = requests.post(
            updateFindingsURL,
            auth=HTTPBasicAuth(
                seccubusUser,
                seccubusPassword),
            data=payload,
            verify=False)
        if r.status_code == 200:
            # error code 200 kan nog steeds error bevatten in de json!
            print ("\t\t\tUpdated finding text")
            # and also update Seccubus with the new status
            currJiraStatus = getJiraStatus(updateText)
            newInfo = updateText + "Current status Jira: " + currJiraStatus
            updateSeccubusComment(
                findInfo,
                status,
                workspace,
                newInfo +
                "\n",
                True)
        else:
            print (
                "Error updating finding text. be careful, it will be send again if you redo this")
        return updateText
    except:
        print(
            "Error updating Seccubus ticket after create. Error: ",
            sys.exc_info())
        exit(1)


def updateSeccubusComment(findInfo, status, workspace, updateTXT, override):
    try:
        # build getFindingsURL from SETTINGS
        updateFindingsURL = SETTINGS['Seccubus'][
            'seccubusServer'] + SETTINGS['Seccubus']['updateFindingsUrl']
        # get user/password from settings
        seccubusUser = SETTINGS['Seccubus']['seccubusUser']
        seccubusPassword = SETTINGS['Seccubus']['seccubusPassword']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    try:
        # using the ticketID (findInfo[7]), we update the finding with the jira
        # text, ID
        payload = "ids%5B%5D=" + findInfo[7] + "&attrs%5Bremark%5D=" + updateTXT + \
            "&attrs%5Bstatus%5D=" + str(status) + "&attrs%5BworkspaceId%5D=" + workspace
        if override:
            payload = payload + "&attrs%5Boverwrite%5D=on"
        r = requests.post(
            updateFindingsURL,
            auth=HTTPBasicAuth(
                seccubusUser,
                seccubusPassword),
            data=payload,
            verify=False)
        if r.status_code == 200:
            print ("\t\t\tUpdated finding text")
        else:
            print ("Error updating finding text. #sadpanda")
            exit(1)
    except:
        print("Error updating Seccubus comment. Error: ", sys.exc_info())
        exit(1)


def updateJiraFinding(findingText, lastRun, statusTXT):
    try:
        jiraURL = SETTINGS['Jira']['jiraApiUrl']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    jiraTicketID = re.search('TicketID: (.+?)\nKey: ', findingText).group(1)
    jiraTicketKey = re.search('Key: (.+?)\n', findingText).group(1)
    commentURL = jiraURL + jiraTicketID + "/comment"
    commentData = '{"body": "Seccubus: this issue has been marked %s in the run of %s"}' % (
        statusTXT, lastRun)
    result = doJiraPost(commentURL, commentData, 'POST')
    if result.status_code == 201:
        result = result.json()
        print (
            ("\t\tticket ID: %s Name: %s comment %s added in Jira") %
            (jiraTicketID, jiraTicketKey, statusTXT))
    else:
        print ("** Error updating ticket in Jira")
        print (result.status_code)
        print (result.text)
        exit(1)


def checkNew(workspace, scanId):
    # status NEW =1
    findings = getFindings(workspace, scanId, 1)
    for findInfo in findings:
        # See if we need to create a new ticket
        JsonData = formatNewFinding(findInfo, workspace, 1)
        lastRun = getLastRun(workspace, scanId)
        if JsonData is not None:
            jiraTicketInfo = createTicket(JsonData)
            updateTXT = updateSeccubusAfterCreate(
                jiraTicketInfo,
                findInfo,
                1,
                workspace)
            updateJiraFinding(updateTXT, lastRun.get('time'), "NEW")


def getJiraStatus(refData):
    # here we get the current jira status of a ticket and return that status
    try:
        jiraURL = SETTINGS['Jira']['jiraApiUrl']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    try:
        jiraTicketKey = re.search('Key: (.+?)\n', refData).group(1)
    except:
        print ("\nError during regular expression to extract Key.", sys.exc_info())
        print ("\n\nData for searching: " + str(refData))
        exit(1)
    getJiraTicket = doJiraPost(jiraURL + jiraTicketKey, None, 'GET')
    # now we have the whole ticket, lets get the current status
    currentJiraStatus = getJiraTicket.json().get(
        'fields').get('status').get('name')
    return currentJiraStatus


def parseFindings(workspace, scanId, findings, statusTXT, status):
    try:
        # build getFindingsURL from SETTINGS
        severityTicketMatch = SETTINGS['General']['severityTicketMatch']
        remarkTXT = SETTINGS['General']['remarkTxt']
        # jiraSeverityMapping=ast.literal_eval(SETTINGS['Jira']['jiraSeverityMapping'])
        if SETTINGS['General']['allwaysMakeJiraLink'] == "True":
            allwaysMakeJiraLink = True
        else:
            allwaysMakeJiraLink = False
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    for findInfo in findings:
        # only those above treshhold
        if findInfo[2] in severityTicketMatch:
            # first of all, lets check if this guy has a jira ticket link
            lastRun = getLastRun(workspace, scanId)
            secCheckString = statusTXT + " " + lastRun.get('time')
            if not findInfo[5] == None and remarkTXT in findInfo[5]:
                if VERBOSE:
                    print(
                        ("\t\tFinding ID %s has a link to Jira and marked %s in Seccubus.") %
                        (findInfo[7], statusTXT))
                if secCheckString in findInfo[5]:
                    print ("\t\tAlready marked %s for this run" % (statusTXT))
                    # since its already marked, lets update seccubus with the
                    # current status
                    currJiraStatus = getJiraStatus(findInfo[5])
                    #print ('\t\tCurrent status in Jira is: %s' % (currJiraStatus))
                    # if findInfo[5] it already contains " Current status in
                    # Jira: xxxx", delete that and add the new status
                    curJiraStatusSeccubus = re.search(
                        'Current status Jira: (.*)\n',
                        findInfo[5])
                    if not curJiraStatusSeccubus is None:
                        # huidige status verwijderen en wat opschonen
                        newInfo = findInfo[5].replace(
                            curJiraStatusSeccubus.group(0),
                            "")
                        newInfo = newInfo.replace("\n\n", "\n")
                        # and finally lets add the most recent actual jira
                        # Status back
                        newInfo = newInfo + \
                            "Current status Jira: " + currJiraStatus
                        # replacement magic to remove the current Jira status
                        lst = list(findInfo)
                        lst[5] = newInfo
                        findInfo = tuple(lst)
                        print(
                            "\t\tUpdating Seccubus call with latest Jira status.")
                        updateSeccubusComment(
                            findInfo,
                            status,
                            workspace,
                            newInfo +
                            "\n",
                            True)
                    else:
                        print ("\t\tNo jira status found, lets add it.")
                        newInfo = findInfo[
                            5] + "Current status Jira: " + currJiraStatus
                        updateSeccubusComment(
                            findInfo,
                            status,
                            workspace,
                            newInfo +
                            "\n",
                            True)
                else:
                    updateJiraFinding(
                        findInfo[5],
                        lastRun.get('time'),
                        statusTXT)
                    updateSeccubusComment(
                        findInfo,
                        status,
                        workspace,
                        secCheckString +
                        "\n",
                        False)
            else:
                if VERBOSE:
                    print(
                        ("\t\tFinding ID %s marked %s but has no link to Jira") %
                        (findInfo[7], statusTXT))
                if allwaysMakeJiraLink:
                    print (
                        "\t\t - Override, allwaysMakeJiraLink =1, so making link anyway")
                    JsonData = formatNewFinding(findInfo, workspace, status)
                    if JsonData is not None:
                        jiraTicketInfo = createTicket(JsonData)
                        updateTXT = updateSeccubusAfterCreate(
                            jiraTicketInfo,
                            findInfo,
                            status,
                            workspace)
                        updateJiraFinding(
                            updateTXT,
                            lastRun.get('time'),
                            statusTXT)
                        updateSeccubusComment(
                            findInfo,
                            status,
                            workspace,
                            secCheckString +
                            "\n",
                            False)
                        # and also update Seccubus with the new status
                        # since its already marked, lets update seccubus with
                        # the current status
                        tmpString = "Key: " + jiraTicketInfo.get('key') + "\n"
                        currJiraStatus = getJiraStatus(tmpString)
                        newInfo = updateTXT + "Current status Jira: " + currJiraStatus
                        updateSeccubusComment(
                            findInfo,
                            status,
                            workspace,
                            newInfo +
                            "\n",
                            True)


def checkNoIssue(workspace, scanId):
    # status NO ISSUE = 4
    findings = getFindings(workspace, scanId, 4)
    parseFindings(workspace, scanId, findings, "NO ISSUE", 4)


def checkGone(workdspace, scanId):
    # status GONE = 5
    findings = getFindings(workspace, scanId, 5)
    parseFindings(workspace, scanId, findings, "GONE", 5)


def checkClosed(workspace, scanId):
    # status CLOSED = 6
    findings = getFindings(workspace, scanId, 6)
    parseFindings(workspace, scanId, findings, "CLOSED", 6)


def checkChanged(workspace, scanId):
    # status CHANGED = 2
    findings = getFindings(workspace, scanId, 2)
    parseFindings(workspace, scanId, findings, "CHANGED", 2)


def checkMasked(workspace, scanId):
    # status  MASKED = 99
    status = 99
    findings = getFindings(workspace, scanId, 99)
    parseFindings(workspace, scanId, findings, "MASKED", 99)


def checkOpen(workspace, scanId):
    # status OPEN = 3
    findings = getFindings(workspace, scanId, 3)
    parseFindings(workspace, scanId, findings, "OPEN", 3)


def checkParams():
    # wonder what we are checking here. Do you think commandline parameters
    #...you are correct!
    # Returns workspaces to handle
    checkWorkspaces = {}
    try:
        # build getFindingsURL from SETTINGS
        updateFindingsURL = SETTINGS['Seccubus'][
            'seccubusServer'] + SETTINGS['Seccubus']['getWorkspacesUrl']
        # get user/password from settings
        seccubusUser = SETTINGS['Seccubus']['seccubusUser']
        seccubusPassword = SETTINGS['Seccubus']['seccubusPassword']
    except:
        print(
            "Error configuring settings to request scans. Check your configuration settings. Error: ",
            sys.exc_info())
        exit(1)
    if len(sys.argv) < 2 or len(sys.argv) > 2:
        print ("""
Helpful as we are, try using --spaces to specify the spaces you want to check.

Valid parameters are:
        --spaces=list #list all the spaces in the database
        --spaces=all #check all spaces available
        --spaces=100,102,103 #comma delimited list of all the spaces you want to check.

    Put together by @ar0xa@protonmail.com
                    ^----^ = twitter
                     ^------------------^ = email
""")
        exit(0)
    parameters = sys.argv[1]
    if not parameters.startswith("--spaces="):
        print(
            "Wrong parameters. Run program without any parameters to see help.")
        exit(1)
    else:
        # since we want names and all that, might as well just get all the
        # workspace names
        try:
            # using the ticketID (findInfo[7]), we update the finding with the
            # jira text, ID
            payload = SETTINGS['Seccubus']['getWorkspacesUrl']
            r = requests.post(
                updateFindingsURL,
                auth=HTTPBasicAuth(
                    seccubusUser,
                    seccubusPassword),
                data=payload,
                verify=False)
            if r.status_code == 200:
                checkWorkspaces = r.json()
            else:
                print ("Error getting all workspaces. #sadpanda")
                exit(1)
        except:
            print("Error getting workspaces. Error: ", sys.exc_info())
            exit(1)
        command = re.search("--spaces=(.*)$", parameters)
        if command.group(1) == "list":
            # just print, dont do anything
            print("Current workspaces are:")
            for space in checkWorkspaces:
                if not space.get('lastScan') == None:
                    print (
                        space.get('id') +
                        ":" +
                        space.get('name') +
                        " Last scan: " +
                        space.get('lastScan'))
                else:
                    print (
                        space.get('id') +
                        ":" +
                        space.get('name') +
                        " Last scan: Never")
            print()
            exit(0)
        elif command.group(1) == "all":
            return checkWorkspaces
        else:
            # here is the challenge. Get all the spaces that were listed and only return those
            # since they are already listed by number, this is just a check that the workspaceID is valid!
            # and remove those who arent listed
            listedWorkspaces = command.group(1).split(',')
            workspacesToCheck = []
            for space in checkWorkspaces:
                if space.get('id') in listedWorkspaces:
                    workspacesToCheck.append({'id': space.get('id'), 'lastScan': space.get(
                        'lastScan'), 'name': space.get('name')})
            return (workspacesToCheck)


def readConfig():
    # read configuration data
    print ("Reading configuration file.")
    try:
        with open('jiraLinkSeccubusSettings.json') as json_settings:
            SETTINGS = json.load(json_settings)
    except IOError as e:
        print ("I/O error({0}): {1}".format(e.errno, e.strerror))
        sys.exit(1)
    except:
        print ("Unexpected error: ", sys.exc_info())
        sys.exit(1)
    print ("Configuration file read successfully.\n")
    return SETTINGS


def print_disclaimer():
    print ("""
jiraLinkSeccubus, Copyright (C) 2015 Ar0xA

jiraLinkSeccubus comes with ABSOLUTELY NO WARRANTY;
This is free software, and you are welcome
to redistribute it under certain conditions; see
attached LICENSE file for details.

""")


if __name__ == "__main__":
    print_disclaimer()
    SETTINGS = readConfig()
    workspacesToCheck = checkParams()
    for workspace in workspacesToCheck:
        workspace = str(workspace.get('id'))
        # get all scan ID's for the workspace we are working on
        wsScanIds = getScans(workspace)
        for scanId in wsScanIds:
            print ("\tChecking issues for scan: " + scanId[1])
            checkNew(workspace, scanId)
            checkGone(workspace, scanId)
            checkNoIssue(workspace, scanId)
            checkClosed(workspace, scanId)
            checkChanged(workspace, scanId)
            checkMasked(workspace, scanId)
            checkOpen(workspace, scanId)