import whois
import re
import csv


class Whoisit:
    
    
    def __init__(self):
        self.domainsDict = {}
        self.headers = []
    
    
    def retrieve(self, domainsList):
        firstRex = re.compile(r'([ \t]*)(\w+ \w+ ?\w* ?\w* ?):^(//)(.*)') # key + value matches
        secondRex = re.compile(r'([ \t]*)(.*)') # value in next line
        
        for domain in domainsList:
            try:
                rawText = whois.whois(domain)
                
            except Exception, e:
                self.domainsDict[domain] = {'ErrorCode' : str(e)}
                
            else:
                lines = rawText.split('\n')
                lnCount = 0
                dictReady = False # checks if a record is ready to be written
                headReady = False # checks if the header has been identified
                ch = ''
                cv = []
                headInd = 0

                while lnCount < len(lines): # stays true till line count is equal or bigger than tot lines
                    line = re.sub(r'\r', '', lines[lnCount])
                    firstMatch = firstRex.match(line)
                    secondMatch = secondRex.match(line)
                    
                    if dictReady:
                        self.domainsDict[domain] = { ch : cv }
                        # reset defaults
                        dictReady = False
                        headReady = False
                        ch = ''
                        cv = []
                    
                    # header was found, but key value pair is not completed yet
                    if headReady:
                        # another indented line to add to the previous
                        if headInd < len(secondMatch.group(1)) and re.sub(r'\s', '', secondMatch.group()) != '':
                            cv.append(secondMatch.group(2).strip())
                            lnCount += 1
                            continue
                        # new non related record: continue without incrementing counter and store the previous
                        else:
                            dictReady = True
                            continue
                        
                    # new header found
                    elif firstMatch:                        
                        # brand new line with header column
                        ch = firstMatch.group(2).strip()
                        headInd = len(firstMatch.group(1))
                        headReady = True
                        # if header column exists already retrieve the list of values
                        if ch in self.domainsDict[domain].keys():
                            cv = self.domainsDict[domain][ch]
                        # column value on the same line
                        if re.sub(r'\s', '', firstMatch.group(3)) != '':
                            cv.append(firstMatch.group(3).strip())
                            dictReady = True
                        
                        lnCount += 1
                        continue
                    
                    # non matching header line
                    else:
                        lnCount += 1
                        continue
    
    def exportToCsv(self):
        pass
    