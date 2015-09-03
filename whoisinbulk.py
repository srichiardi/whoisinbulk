import whois
import re


class Whoisit:
    
    
    def __init__(self):
        self.domainsDict = {}
        self.headers = []
    
    
    def retrieve(self, domainsList):
        
        for domain in domainsList:
            try:
                rawText = whois.whois(domain)
                
            except Exception:
                self.domainsDict[domain] = {'ErrorCode' : 'Unable to retrieve data'}
                
            else:
                reList = []
                
                for line in rawText.split('\n'):
                    matchStr = re.findall(r'(\w+\s\w+\s?\w*\s?\w*\s?:[^\\\\]\s*.*)',line.replace(r'\r',''))
                    reList.extend(matchStr)
                
            
    
    
    def exportToCsv(self):
        pass