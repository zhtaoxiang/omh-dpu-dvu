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

DATA_CONTENT = bytearray([
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
])

class TestGroupManager(object):
    def __init__(self, face, identityName, groupManagerName, dKeyDatabaseFilePath):
        # Set up face
        self.face = face
        #self.loop = eventLoop

        # Set up the keyChain.
        identityStorage = MemoryIdentityStorage()
        privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())

        self.certificateName = self.keyChain.createIdentityAndCertificate(identityName)
        self.keyChain.getIdentityManager().setDefaultIdentity(identityName)

        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        self.dKeyDatabaseFilePath = dKeyDatabaseFilePath
        try:
            os.remove(self.dKeyDatabaseFilePath)
        except OSError:
            # no such file
            pass

        self.manager = GroupManager(
          identityName, groupManagerName,
          Sqlite3GroupManagerDb(self.dKeyDatabaseFilePath), 2048, 1,
          self.keyChain)

        self.memoryContentCache = MemoryContentCache(self.face)
        self.memoryContentCache.registerPrefix(identityName, self.onRegisterFailed, self.onDataNotFound)

        self.generateGroupKeyFlag = False
        return

    def setManager(self):
        schedule1 = Schedule()
        interval11 = RepetitiveInterval(
          Schedule.fromIsoString("20150825T000000"),
          Schedule.fromIsoString("20150827T000000"), 5, 10, 2,
          RepetitiveInterval.RepeatUnit.DAY)
        interval12 = RepetitiveInterval(
          Schedule.fromIsoString("20150825T000000"),
          Schedule.fromIsoString("20150827T000000"), 6, 8, 1,
          RepetitiveInterval.RepeatUnit.DAY)
        interval13 = RepetitiveInterval(
          Schedule.fromIsoString("20150827T000000"),
          Schedule.fromIsoString("20150827T000000"), 7, 8)
        schedule1.addWhiteInterval(interval11)
        schedule1.addWhiteInterval(interval12)
        schedule1.addBlackInterval(interval13)

        self.manager.addSchedule("schedule1", schedule1)

    # Keep trying until member certificate is retrieved
    def retrieveMemeberCertificate(self, memberName):
        # TODO: for now, we ignore the ksk-timestamp component in this request
        memberA = Name(memberName)
        interest = Interest(memberA)
        interest.setInterestLifetimeMilliseconds(4000)
        print "Retrieving member certificate: " + interest.getName().toUri()
        self.face.expressInterest(interest, self.onMemberCertificateData, self.onMemberCertificateTimeout)
    
    def onMemberCertificateData(self, interest, data):
        print "Member certificate with name retrieved: " + data.getName().toUri() + "; member added to group!"
        self.generateGroupKeyFlag = True
        self.manager.addMember("schedule1", data)

    def onMemberCertificateTimeout(self, interest):
        print "Member certificate interest times out: " + interest.getName().toUri()
        self.retrieveMemeberCertificates(interest.getName())
        return

    def publishGroupKeys(self):
        timePoint1 = Schedule.fromIsoString("20150825T093000")
        result = self.manager.getGroupKey(timePoint1)

        # The first is group public key, E-key
        # The rest are group private keys encrypted with each member's public key, D-key
        for i in range(0, len(result)):
            self.memoryContentCache.add(result[i])
            print "Publish key name: " + str(i) + " " + result[i].getName().toUri()

    def onDataNotFound(self, prefix, interest, face, interestFilterId, filter):
        print "Data not found for interest: " + interest.getName().toUri()
        if interest.getExclude():
            print "Interest has exclude: " + interest.getExclude().toUri()
        return

    def onRegisterFailed(self, prefix):
        print "Prefix registration failed"
        return

if __name__ == "__main__":
    print "Start NAC group manager test"
    #loop = asyncio.get_event_loop()
    face = Face()

    identityName = Name("/org/openmhealth/zhehao/data/fitness")
    groupManagerName = Name("/org/openmhealth/zhehao/data/fitness")

    testGroupManager = TestGroupManager(face, identityName, groupManagerName, "policy_config/manager-d-key-test.db")
    testGroupManager.setManager()
    testGroupManager.retrieveMemeberCertificate(Name("/ndn/member0/KEY/"))
    testGroupManager.publishGroupKeys()
    
    while True:
        face.processEvents()

        if testGroupManager.generateGroupKeyFlag:
            testGroupManager.publishGroupKeys()
            testGroupManager.generateGroupKeyFlag = False

        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

