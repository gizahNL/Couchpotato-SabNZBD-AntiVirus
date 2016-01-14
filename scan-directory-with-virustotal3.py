#!/usr/local/bin/python2.7

'''
This is a Python script to scan a directory (and subdirectories) for files with certain extensions and compares them against virustotal.com.
If the script finds an infected file, it renames it.
The script is meant to be used as SABnzbd postprocessing script

Virustotal.com gives feedback based on the md5sum hash of a file.

Please note: virustotal requests are "limited to at most 4 requests of any nature in any given 1 minute time frame",
so do NOT use this script to scan your whole disk

This Python script is modified to use the V2 API of virustotal.com
'''

import os
import hashlib
import sys
import urllib
import urllib2
import shutil
import json
import simplejson

apiKey = "XXXX"
vitotalkey = "XXX"
srv = "http://10.0.14.12:5050"


# Extensions to be scanned (note the dot at the beginning):
extlist = [ '.exe', '.com', '.apk' ]


# Function to calculate md5sum of a file
def md5_of_file(filename):
	md5 = hashlib.md5()
	with open(filename,'rb') as f: 
	    for chunk in iter(lambda: f.read(8192), b''): 
		 md5.update(chunk)
	return md5.hexdigest()


# Function to determine if virustotal says the md5sum is a virus/infection
def virustotal_scan(md5value):

	number = 0
	found = False
	names = ''

	url = "https://www.virustotal.com/vtapi/v2/file/report"
	parameters = {"resource": md5value,
		      "apikey": vitotalkey}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)

	response = urllib2.urlopen(req)
	html = response.read()
	response_dict = simplejson.loads(html)
	number = response_dict.get("positives")
	
	if number >=6:
		found = True
	return (found,names,number)


##############################################
##############################################
################# MAIN #######################
##############################################
##############################################

# Check the input parameter; there should be a valid directory name:

if len(sys.argv) < 2:
    sys.exit('Usage: %s directory-name' % sys.argv[0])

dirname = sys.argv[1]

if not os.path.exists(dirname):
    sys.exit('ERROR: Directory not found' % sys.argv[1])

# OK, let's start with scanning:

scannedfiles = 0 # no more than 4 per minute ...
virusfound = False

url = srv+"/api/"+apiKey+"/media.list?release_status=snatched&status=active"
u = urllib2.urlopen(url)
obj = json.load(u)
u.close()

for root, dirs, files in os.walk(dirname):
    for file in files:
	extension = os.path.splitext(file)[1].lower()
	if extension in extlist:
		#print "extension is", extension
        	fullfilename = os.path.join(root, file)
		md5 = md5_of_file(fullfilename)
		#print fullfilename, md5
		virusfound, virusnames, number = virustotal_scan(md5)
		if virusfound:
			print "Virus found in", fullfilename, "!\n Info:\n", virusnames
			newfilename = fullfilename + '__INFECTED'
			os.rename(fullfilename, newfilename)
			shutil.rmtree(sys.argv[1])
			print "\n\nI deleted ",sys.argv[1]," for you!\n\n"
			nzb = sys.argv[2]
			nzb = nzb.split(".cp(")
			imdb = nzb[-1]
			imdb = imdb.replace(").nzb","")
			del nzb[-1]
			nzb='.cp('.join(nzb)
			print "\n\n"
			url = srv+"/api/"+apiKey+"/media.list?release_status=snatched&status=active"
			u = urllib2.urlopen(url)
			obj = json.load(u)
			u.close()
                	for x in range(0, len(obj['movies'])):
                    		if imdb == obj['movies'][x]['library']['info']['imdb']:
                        		url = srv+"/api/"+apiKey+"/movie.searcher.try_next?id="+str(obj['movies'][x]['id'])
                        		u = urllib2.urlopen(url)
                        		u.close()
                        		print "\n\n I gave CP the command to ignore this NZB and search again"
				else:
					dummy = 0
					#print "No Virus found"
		scannedfiles += 1
		if scannedfiles > 4:
			print "Warning: you have now scanned more than 4 files ..."


if virusfound:
	sys.exit(number)
else:
	sys.exit(0)
