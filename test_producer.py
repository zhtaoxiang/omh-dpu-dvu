import os, time
from pyndn import Name, Data, Face
from pyndn.util import Blob, MemoryContentCache
from pyndn.encrypt import Producer, Schedule, Sqlite3ProducerDb, EncryptedContent
from pyndn.encrypt.algo import Encryptor, AesAlgorithm, RsaAlgorithm
from pyndn.encrypt.algo import EncryptParams, EncryptAlgorithmType
from pyndn.security import KeyChain, RsaKeyParams
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage, MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

DATA_CONTENT = bytearray([
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
])

class TestProducer(object):
    def __init__(self, face):
        # Set up face
        self.face = face

        # Set up the keyChain.
        identityStorage = MemoryIdentityStorage()
        privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())
        identityName = Name("TestProducer")
        self.certificateName = self.keyChain.createIdentityAndCertificate(identityName)
        self.keyChain.getIdentityManager().setDefaultIdentity(identityName)

        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        self.databaseFilePath = "policy_config/test_producer.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass
        
        self.testDb = Sqlite3ProducerDb(self.databaseFilePath)
        prefix = Name("/prefix")
        suffix = Name("/a/b/c")

        self.producer = Producer(prefix, suffix, self.face, self.keyChain, self.testDb)

        self.memoryContentCache = MemoryContentCache(self.face)
        self.memoryContentCache.registerPrefix(prefix, self.onRegisterFailed, self.onDataNotFound)
        return

    def onDataNotFound(self, prefix, interest, face, interestFilterId, filter):
        print "Data not found for interest: " + interest.getName().toUri()
        return

    def onRegisterFailed(self, prefix):
        print "Prefix registration failed"
        return

    def createContentKey(self, timeSlot):
        print "Creating content key"
        contentKeyName = self.producer.createContentKey(timeSlot, self.onEncryptedKeys)

    def produce(self, timeSlot):
        emptyData = Data()
        self.producer.produce(emptyData, timeSlot, Blob(DATA_CONTENT, False))
        producedName = emptyData.getName()

        # Test the length of encrypted data
        
        # dataBlob = emptyData.getContent()
        # dataContent = EncryptedContent()
        # dataContent.wireDecode(dataBlob)
        # encryptedData = dataContent.getPayload()
        # print len(encryptedData)

        self.memoryContentCache.add(emptyData)
        print "Produced data with name " + producedName.toUri()

    def onEncryptedKeys(self, keys):
        print "onEncryptedKeys called"
        if not keys:
            print "onEncryptedKeys: no keys in callback!"
        for i in range(0, len(keys)):
            print "onEncryptedKeys: produced encrypted key " + keys[i].getName().toUri()
            self.memoryContentCache.add(keys[i])
        return

if __name__ == "__main__":
    print "Start NAC producer test"
    face = Face()
    testProducer = TestProducer(face)
    testTime1 = Schedule.fromIsoString("20150825T080000")
    testProducer.createContentKey(testTime1)
    testProducer.produce(testTime1)
    print "Produced"
    # TODO: getting the encrypted C-key to the group manager

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

