import os, time
from pyndn import Name, Face, Data, Interest, Exclude
from pyndn.threadsafe_face import ThreadsafeFace
from pyndn.util import Blob, MemoryContentCache
from pyndn.encrypt import GroupManager, Sqlite3GroupManagerDb, EncryptedContent
from pyndn.encrypt import Schedule, RepetitiveInterval, DecryptKey, EncryptKey

from pyndn.security import KeyChain, RsaKeyParams
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage, MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

import trollius as asyncio
from pyndn.encoding import ProtobufTlv

import producer.repo_command_parameter_pb2 as repo_command_parameter_pb2
import producer.repo_command_response_pb2 as repo_command_response_pb2

DATA_CONTENT = bytearray([
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
])

class TestGroupManager(object):
    def __init__(self, face, groupManagerName, dataType, readAccessName, dKeyDatabaseFilePath):
        # Set up face
        self.face = face
        #self.loop = eventLoop

        # Set up the keyChain.
        identityStorage = MemoryIdentityStorage()
        privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())

        self.certificateName = self.keyChain.createIdentityAndCertificate(groupManagerName)

        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        self.dKeyDatabaseFilePath = dKeyDatabaseFilePath
        try:
            os.remove(self.dKeyDatabaseFilePath)
        except OSError:
            # no such file
            pass

        self.manager = GroupManager(
          groupManagerName, dataType,
          Sqlite3GroupManagerDb(self.dKeyDatabaseFilePath), 2048, 1,
          self.keyChain)

        self.memoryContentCache = MemoryContentCache(self.face)
        self.memoryContentCache.registerPrefix(Name(groupManagerName).append("READ"), self.onRegisterFailed, self.onDataNotFound)
        self.face.registerPrefix(readAccessName, self.onAccessInterest, self.onAccessTimeout)

        self.updateGroupKeys = False
        return

    def onAccessInterest(self, prefix, interest, face, interestFilterId, filter):
        print "On Access request interest: " + interest.getName().toUri()
        certInterest = Interest(interest.getName().getSubName(4))
        certInterest.setName(certInterest.getName().getPrefix(-1))
        certInterest.setInterestLifetimeMilliseconds(2000)

        self.face.expressInterest(certInterest, 
          lambda memberInterest, memberData: self.onMemberCertificateData(memberInterest, memberData, interest), 
          lambda memberInterest: self.onMemberCertificateTimeout(memberInterest, interest) );
        print "Retrieving member certificate: " + certInterest.getName().toUri()

        return

    def onAccessTimeout(self, prefix):
        print "Prefix registration failed: " + prefix.toUri()
        return

    def onRepoData(self, interest, data):
        #print "received repo data: " + interest.getName().toUri()
        return

    def onRepoTimeout(self, interest):
        #print "repo command times out: " + interest.getName().getPrefix(-1).toUri()
        return

    def setManager(self):
        schedule1 = Schedule()
        interval11 = RepetitiveInterval(
          Schedule.fromIsoString("20161001T000000"),
          Schedule.fromIsoString("20161031T000000"), 0, 24, 1,
          RepetitiveInterval.RepeatUnit.DAY)
        schedule1.addWhiteInterval(interval11)
        
        self.manager.addSchedule("schedule1", schedule1)

    def onMemberCertificateData(self, interest, data, accessInterest):
        print "Member certificate with name retrieved: " + data.getName().toUri() + "; member added to group!"
        self.manager.addMember("schedule1", data)
        self.updateGroupKeys = True

        accessResponse = Data(accessInterest.getName())
        accessResponse.setContent("granted")
        self.face.putData(accessResponse)

    def onMemberCertificateTimeout(self, interest, accessInterest):
        print "Member certificate interest times out: " + interest.getName().toUri()
        newInterest = Interest(interest)
        newInterest.refreshNonce()
        self.face.expressInterest(newInterest, 
          lambda memberInterest, memberData: self.onMemberCertificateData(memberInterest, memberData, accessInterest), 
          lambda memberInterest: self.onMemberCertificateTimeout(memberInterest, accessInterest))
        return

    def publishGroupKeys(self):
        timePoint1 = Schedule.fromIsoString("20161024T083000")
        result = self.manager.getGroupKey(timePoint1)

        # The first is group public key, E-key
        # The rest are group private keys encrypted with each member's public key, D-key
        for i in range(0, len(result)):
            self.memoryContentCache.add(result[i])
            self.initiateContentStoreInsertion("/ndn/edu/ucla/remap/ndnfit/repo", result[i])
            print "Publish key name: " + str(i) + " " + result[i].getName().toUri()

        self.updateGroupKeys = False

    def onDataNotFound(self, prefix, interest, face, interestFilterId, filter):
        print "Data not found for interest: " + interest.getName().toUri()
        if interest.getExclude():
            print "Interest has exclude: " + interest.getExclude().toUri()
        return

    def onRegisterFailed(self, prefix):
        print "Prefix registration failed"
        return

    def initiateContentStoreInsertion(self, repoCommandPrefix, data):
        fetchName = data.getName()
        parameter = repo_command_parameter_pb2.RepoCommandParameterMessage()
        # Add the Name.
        for i in range(fetchName.size()):
            parameter.repo_command_parameter.name.component.append(
              fetchName[i].getValue().toBytes())

        # Create the command interest.
        interest = Interest(Name(repoCommandPrefix).append("insert")
          .append(Name.Component(ProtobufTlv.encode(parameter))))
        self.face.makeCommandInterest(interest)

        self.face.expressInterest(interest, self.onRepoData, self.onRepoTimeout)

if __name__ == "__main__":
    print "Start NAC group manager test"
    #loop = asyncio.get_event_loop()
    face = Face()

    groupManagerName = Name("/org/openmhealth/haitao/")
    readAccessName = Name("/org/openmhealth/haitao/read_access_request")
    dataType = Name("fitness")

    testGroupManager = TestGroupManager(face, groupManagerName, dataType, readAccessName, "policy_config/manager-d-key-test.db")
    testGroupManager.setManager()

    testGroupManager.publishGroupKeys()
    
    while True:
        face.processEvents()

        if testGroupManager.updateGroupKeys:
            testGroupManager.publishGroupKeys()

        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

