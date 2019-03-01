#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# ijiami

#reference https://pyopenssl.org/en/0.15.1/api/crypto.html?highlight=get_extension_count


import os
import sys
import zipfile
import shutil
import time
import subprocess
from biplist import *

#pip install pyopenssl
from OpenSSL.crypto import FILETYPE_ASN1, load_certificate



class IpaParse(object):
    ipaPath = ""
    AppPath = ""
    AppName = ""
    MachoPath = ""
    UnZipDir = ""
    ipaNewName = ""
    provisionPath = ""
    entitFilePath = ""
    provisionName = ""
    bundleID = ""


    def __init__(self, ipa_path=None):
        if ipa_path is None:
            return
        self.initIpaPath(ipa_path)

    def initIpaPath(self, ipa_path):
        self.ipaPath = ipa_path


    def un_zip(self, file_name):
        """unzip zip file"""
        listFile = os.path.splitext(file_name)
        unzip_path = listFile[0]
        if os.path.isdir(unzip_path):
            pass
        else:
            os.mkdir(unzip_path)

        zip_file = zipfile.ZipFile(file_name,'r')


        for f in zip_file.namelist():
            zip_file.extract(str(f), str(unzip_path))

        zip_file.close()

        return unzip_path


    def check_is_crypted(self, exe_path):
        #check wheather ipa is crypted

        try: 
            cmd_if_hasBitcode = "otool -l \"%s\" | grep -B 2 crypt" %(exe_path)
            rltstr = subprocess.check_output(cmd_if_hasBitcode,
                                    stderr = subprocess.STDOUT,
                                             shell=True)

        except subprocess.CalledProcessError as e:
            out_byte = e.output  # Output generated before error
            #code = e.returncode  # Return code
            #error.errorOccured(error.ipa_check_bitcode_error,out_byte)
        else:
            if "cryptid 1" in rltstr:
                return False
            else:
                return True


    def upzip_one_ipa(self):
        print "unzip ipa"
        unzip_path = self.un_zip(self.ipaPath)
        self.UnZipDir = unzip_path

        exe_path_dir = unzip_path + "/Payload"

        for filename in os.listdir(exe_path_dir):
            fp = os.path.join(exe_path_dir, filename)
            if os.path.isdir(fp) and ".app" in fp:
                file_name_list = os.path.splitext(filename)
                self.AppName = file_name_list[0]
                self.AppPath = fp
                break
        
        #get macho path
        infoDic = readPlist(os.path.join(self.AppPath, "Info.plist"))
        self.AppPath = unicode(self.AppPath,'utf-8')
        self.AppPath = self.AppPath.encode('utf-8')

        machoName = infoDic["CFBundleExecutable"]
        machoName = machoName.encode('utf-8')
        
        self.MachoPath = os.path.join(self.AppPath, machoName)
        #self.MachoPath = unicode(self.MachoPath,'utf-8')
        print self.MachoPath
        print "unzip ipa done"



    def cleanupTmpFile(self):
        if self.UnZipDir:
            shutil.rmtree(self.UnZipDir, ignore_errors=True)


    def toPakgeIpa(self,saveTempDir):
        print 'pakge ipa'

        # chmod -RH u+w,go-w,a+rX
        try:
          cmd_chmod = "chmod -RH u+w,go-w,a+rX " + self.AppPath
          os.popen(cmd_chmod)
        except subprocess.CalledProcessError as  e:
          print "error"
        else:
          print "add u+w  done"
        


        os.chdir(self.UnZipDir)  # 设置工作目录

        newIpaPath = ""
        if self.ipaNewName:
          newIpaPath = self.ipaNewName
          if '.ipa' not in newIpaPath:
            newIpaPath += ".ipa"
        else:
          newIpaPath = self.AppName + "_" + time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time())) + ".ipa"

        try:
          cmd_zip = "zip -qry --recurse-paths    -o ../%s     ." % newIpaPath

          subprocess.check_output(cmd_zip,
                                  stderr=subprocess.STDOUT,
                                  shell=True)

        except subprocess.CalledProcessError as e:
          out_byte = e.output  # Output generated before error
          # code = e.returncode  # Return code

        else:
          print 'pakge ipa  done'
          lastWorkPath = os.path.realpath(os.path.join(self.ipaPath,
                                                       ".."
                                                       ))

          os.chdir(os.path.dirname(lastWorkPath))  # 设置工作目录

          if not saveTempDir:
            print self.UnZipDir
            shutil.rmtree(os.path.realpath(self.UnZipDir), ignore_errors=True)
          


    def toGetEmbeddedPlist(self):

        entitlements_full = os.path.join(os.path.dirname(self.provisionPath), "entitlements_full_tmp.plist")
        try:
            cmd_readprovision = "security cms -D -i \"%s\" > \"%s\" " %(self.provisionPath, entitlements_full) 
            rltstr = subprocess.check_output(cmd_readprovision,
                                    stderr = subprocess.STDOUT,
                                             shell=True)

        except subprocess.CalledProcessError as e:
            out_byte = e.output  # Output generated before error
            code = e.returncode  # Return code
            print "error is error" 
            return code
            #error.errorOccured(error.ipa_check_bitcode_error,out_byte)

        else:
            print 'read provision done'
        
        
        print "readPlist"
        entitlementsDic = readPlist(entitlements_full)
        
        #print entitlementsDic["ExpirationDate"]
        #print entitlementsDic["TeamIdentifier"]
        #print entitlementsDic["TeamName"]

        #get sha1 of private key contain entitlements_full
        sha1List = []
        CertificatesArr = entitlementsDic["DeveloperCertificates"]
        for x in CertificatesArr:
          cert = load_certificate(FILETYPE_ASN1, x)
          certIssue = cert.get_issuer()
          subject = cert.get_subject()
          
          #print subject.organizationName
          #print subject.organizationalUnitName
          #print subject.commonName

           
          if cert.has_expired():
            print "========================== \"%s\" is out of date" %(subject.commonName)
          else:
            #print subject.organizationName
            #print subject.organizationalUnitName
            #print subject.commonName
            shastr = cert.digest("sha1").decode('utf-8')
            shastr = shastr.replace(':','')
            sha1List.append(shastr)
            #print shastr


        #print sha1List

        #get private key on mac
        findidentityRlt = ""
        try:
            findidentity = "security find-identity -v -p codesigning"
            findidentityRlt = subprocess.check_output(findidentity,
                                    stderr = subprocess.STDOUT,
                                             shell=True)

        except subprocess.CalledProcessError as e:
            out_byte = e.output  # Output generated before error
            code = e.returncode  # Return code
            print "error is error" 
            return code
            #error.errorOccured(error.ipa_check_bitcode_error,out_byte)
        else:
            print 'get private key on mac done'

        listIds = findidentityRlt.splitlines()
        for line in listIds:
          index = line.find(") ")
          if index > 0:
            sha = line[index + 2: index + 2 + 40]
            if sha in sha1List:
              self.provisionName = sha
              break
            
        if len(self.provisionName) < 1:
          print "no private key on mac"
          return -2
          

        teamId = entitlementsDic["Entitlements"]["com.apple.developer.team-identifier"]
        appId = entitlementsDic["Entitlements"]["application-identifier"]

        bundleIDTmp = appId[appId.find(teamId) + len(teamId) + 1:] 
        self.bundleID = bundleIDTmp
        #print self.bundleID

        entitFilePath = os.path.realpath (os.path.join(os.path.dirname(self.provisionPath), "entitlements.plist"))
        #writePlist(entitlementsDic["Entitlements"], entitFilePath)
        # entitlements.plist
        try:
            findidentity = "/usr/libexec/PlistBuddy -x -c \"print :Entitlements \" %s  > \"%s\""  %(entitlements_full, entitFilePath)
            findidentityRlt = subprocess.check_output(findidentity,
                                    stderr = subprocess.STDOUT,
                                             shell=True)

        except subprocess.CalledProcessError as e:
            out_byte = e.output  # Output generated before error
            code = e.returncode  # Return code
            print "error is error" 
            return code
        else:
            self.entitFilePath = entitFilePath


        return 0


    def removeOldFile(self):
        # delete old  _CodeSignature
        codeSignaturePath = os.path.join(self.AppPath,"_CodeSignature")
        if os.path.exists(codeSignaturePath):
         shutil.rmtree(codeSignaturePath)

        #delete old embedded.mobileprovision
        embededPath = os.path.join(self.AppPath, "embedded.mobileprovision")
        if os.path.exists(embededPath):
          os.remove(embededPath)

        #delete plugin
        pluginsPath = os.path.join(self.AppPath, "PlugIns")
        if os.path.exists(pluginsPath):
          shutil.rmtree(pluginsPath)

        #delete watch
        watchPath = os.path.join(self.AppPath, "Watch")
        if os.path.exists(watchPath):
          shutil.rmtree(watchPath)


    def resignFramework(self):

      allowFramework = [".framework",".dylib",".so",".dll"]

      Frameworks = os.path.join(self.AppPath,"Frameworks")
      if os.path.exists(Frameworks):
        for filename in os.listdir(Frameworks):
            fp = os.path.join(Frameworks, filename)
            try:
              resignCmd = "codesign --continue -f -s \"%s\"  \"%s\"" % (self.provisionName, fp)
              os.popen(resignCmd)

            except subprocess.CalledProcessError as e:
              return e.returncode
            else:
              print "resign Frameworks done"
        
      if os.path.exists(self.AppPath):
        for filename in os.listdir(self.AppPath):
              rltarr = os.path.splitext(filename)
              if len(rltarr) == 2:
                ext = rltarr[1]
                if ext in allowFramework:
                  fp = os.path.join(Frameworks, filename)
                  try:
                    resignCmd = "codesign --continue -f -s \"%s\"  \"%s\"" % (self.provisionName, fp)
                    os.popen(resignCmd)
                  except subprocess.CalledProcessError as e:
                    print  e.output
                    return e.returncode
                  else:
                    print "resign Frameworks done"
                


    def autoResign(self):
      # self.AppPath
      # configuration for iOS build setting

      rlt = self.toGetEmbeddedPlist()
      if rlt != 0:
          print "get plist failed"
          return rlt

      self.removeOldFile()


      embededPath = os.path.join(self.AppPath, "embedded.mobileprovision")
      shutil.copy(self.provisionPath,embededPath)

      #modify Info.plist 中的 bundle id
      infoPath = os.path.join(self.AppPath, "Info.plist")
      try:
        plist = readPlist(infoPath)
        plist["CFBundleIdentifier"] = self.bundleID

        newInfoPath = os.path.join(self.AppPath,"newInfo.plist")
        writePlist(plist, newInfoPath)

        os.remove(infoPath)
        os.rename(newInfoPath,infoPath)
      except (InvalidPlistException, NotBinaryPlistException), e:
        print "Not a plist:", e
        return e.returncode

      self.resignFramework()

      #copy self.entitFilePath to .app dir
      entitlementsPlist = os.path.join(os.path.dirname(self.AppPath), "entitlements.plist")
      shutil.copy(self.entitFilePath,entitlementsPlist)


      os.chdir(os.path.dirname(self.AppPath))  
      try:
        resignCmd = "codesign -f -s \"%s\" --no-strict --entitlements \"%s\" \"%s\"" % (self.provisionName, entitlementsPlist, self.AppPath)
        os.popen(resignCmd)


      except subprocess.CalledProcessError as e:
        print  e.output
        return e.returncode
      else:
        chmodcmd = "chmod +x \"%s\" " %(self.MachoPath)
        os.popen(chmodcmd)
        
        if os.path.exists(entitlementsPlist):
          os.remove(entitlementsPlist)

        return 0
      


ipa = IpaParse()




def main():


  #ipaPath = "/Users/Rain/Desktop/signer/adhoc.ipa"
  #provisionPath = "/Users/Rain/Desktop/signer/embedded.mobileprovision"

  if len(sys.argv) != 3:
    print "first arg is path of ipa，second arg is path of embedded.mobileprovision"
    return
  


  ipaPath = os.path.realpath(sys.argv[1])
  if not os.path.exists(ipaPath):
    print "ipa not exists"
    return

  provisionPath = os.path.realpath(sys.argv[2])
  if not os.path.exists(provisionPath):
    print "*.mobileprovision not exists"
    return

  ipa.ipaPath = ipaPath
  ipa.provisionPath = provisionPath

  ipa.upzip_one_ipa()
  if not  ipa.check_is_crypted(ipa.MachoPath):
     print "ipa must not crypted"
     return -1
  
  ipa.autoResign()
  ipa.toPakgeIpa(False)




if  __name__ == '__main__':
    main()
  

