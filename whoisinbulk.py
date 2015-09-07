import whois
import re
import csv
from datetime import datetime
import sys


class Whoisit:
    
    def __init__(self):
        self.domainsDict = {}
        self.headers = ['Domain']
    
    
    def retrieve(self, domainsList):
        firstRex = re.compile(r'([ \t]*)([A-Z][a-z\']+ ?\w* ?\w* ?\w* ?):(?!//)(.*)') # key + value matches
        secondRex = re.compile(r'([ \t]*)(.*)') # value in next line
        
        for domain in domainsList:
            
            self.domainsDict[domain] = {}
            
            try:
                rawText = whois.whois(domain)
                
            except Exception:
                wiErrMsg = 'No match for %s' % domain
                self.domainsDict[domain] = {'ErrorCode' : [wiErrMsg] }
                
            else:
                lines = rawText.text.split('\n')
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
                        # write previous record and reset defaults
                        self.domainsDict[domain][ch] = cv
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
                        
                        # update list of headers
                        if ch not in self.headers:
                            self.headers.append(ch)
                        
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
    
    def importDomains(self):
        pass
    
    
    def exportToCsv(self, folderPath):
        
        # append ErroCode filed last in the headers list
        self.headers.append('ErrorCode')
        
        # prepare the csv file
        folderPath = folderPath.replace("\\","/")
        fileName = folderPath + "/whosinbulk_export_%s.csv" % datetime.now().strftime("%Y%m%d_%H-%M-%S")
        csvFileToWrite = open(fileName, 'ab')
        csvWriter = csv.DictWriter(csvFileToWrite, self.headers, restval='', delimiter=',',
                                   extrasaction='ignore', dialect='excel', quotechar='"')
        csvWriter.writeheader()
        
        # csv writing loop
        for domain in self.domainsDict.keys():
            
            nextField = True
            
            while nextField == True:
                nextField = False
                tempDict = { self.headers[0] : domain }
                for keyField in self.domainsDict[domain].keys():
                    try:
                        value = self.domainsDict[domain][keyField].pop()
                        nextField = True
                    except IndexError:
                        value = ''
                    except AttributeError:
                        print 'Attrib Error:\ndomain: %s\nfield: %s\nvalue: %s' % (domain, keyField, self.domainsDict[domain][keyField])
                        sys.exit()
                    finally:
                        tempDict[keyField] = value
                
                # write tempDict to csv file
                if nextField:
                    csvWriter.writerow(tempDict)
        
        # close csv file
        csvFileToWrite.close()
        
        print 'Export completed. Data saved in %s' % fileName
        
    