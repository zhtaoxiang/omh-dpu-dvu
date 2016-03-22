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

class DPUProducer(object):
    def __init__(self, face, memoryContentCache, producerPrefix, producerSuffix, keyChain, certificateName, databaseFilePath):
        # Set up face
        self.face = face

        self.certificateName = Name(certificateName)
        self.keyChain = keyChain

        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        # Reset producer db
        self.databaseFilePath = databaseFilePath
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass
        
        self.testDb = Sqlite3ProducerDb(self.databaseFilePath)

        self.producer = Producer(producerPrefix, producerSuffix, self.face, self.keyChain, self.testDb)
        self.memoryContentCache = memoryContentCache
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

    def produce(self, timeSlot, content):
        emptyData = Data()
        self.producer.produce(emptyData, timeSlot, Blob(content, False))
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

    nameString = "/org/openmhealth/zhehao/data/fitness/physical_activity/bout/bounding_box"
    identityName = Name(nameString)
    prefix = Name(nameString)
    suffix = Name()
    databaseFilePath = "policy_config/test_producer.db"

    testProducer = DPUProducer(face, identityName, prefix, suffix, databaseFilePath)

    testTime1 = Schedule.fromIsoString("20160320T080000")
    testProducer.createContentKey(testTime1)
    testProducer.produce(testTime1, DATA_CONTENT)
    print "Produced"
    # TODO: getting the encrypted C-key to the group manager

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

