import os, time, base64
from pyndn import Name, Data, Face
from pyndn.util import Blob, MemoryContentCache
from pyndn.encrypt import Consumer, Sqlite3ConsumerDb, EncryptedContent

from pyndn.security import KeyType, KeyChain, RsaKeyParams
from pyndn.security.certificate import IdentityCertificate
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import BasicIdentityStorage, FilePrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

DATA_CONTENT = bytearray([
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
])

class DPUConsumer(object):
    def __init__(self, face, memoryContentCache, groupName, keyChain, certificateName, databaseFilePath):
        # Set up face
        self.face = face

        self.databaseFilePath = databaseFilePath
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass

        self.groupName = Name(groupName)
        self.certificateName = Name(certificateName)
        self.keyChain = keyChain

        consumerKeyName = IdentityCertificate.certificateNameToPublicKeyName(self.certificateName)
        consumerCertificate = identityStorage.getCertificate(self.certificateName, True)
        self.consumer = Consumer(
          face, self.keyChain, self.groupName, consumerKeyName,
          Sqlite3ConsumerDb(self.databaseFilePath))

        # TODO: Read the private key to decrypt d-key...this may or may not be ideal
        base64Content = None
        with open(privateKeyStorage.nameTransform(consumerKeyName.toUri(), ".pri")) as keyFile:
            base64Content = keyFile.read()
        der = Blob(base64.b64decode(base64Content), False)
        self.consumer.addDecryptionKey(consumerKeyName, der)

        self.memoryContentCache = memoryContentCache
        self.memoryContentCache.add(consumerCertificate)

        # self.memoryContentCache.registerPrefix(identityName, self.onRegisterFailed, self.onDataNotFound)
        
        # print "Consumer certificate name: " + self.certificateName.toUri()
        # print "Consumer key name: " + consumerKeyName.toUri()
        return

    def consume(self, contentName):
        self.consumer.consume(contentName, self.onConsumeComplete, self.onConsumeFailed)

    def onConsumeComplete(self, data, result):
        print "Consume complete for data name: " + data.getName().toUri()
        
        # Test the length of encrypted data

        # dataBlob = data.getContent()
        # dataContent = EncryptedContent()
        # dataContent.wireDecode(dataBlob)
        # encryptedData = dataContent.getPayload()
        # print len(encryptedData)

        if result.equals(Blob(DATA_CONTENT, False)):
            print "Got expected content"
        else:
            print "Didn't get expected content"
        return

    def onConsumeFailed(self, code, message):
        print "Consume error " + str(code) + ": " + message

if __name__ == "__main__":

    # Set up the keyChain.
    # identityStorage = BasicIdentityStorage()
    # privateKeyStorage = FilePrivateKeyStorage()
    # self.keyChain = KeyChain(
    #   IdentityManager(identityStorage, privateKeyStorage),
    #   NoVerifyPolicyManager())
    # identityName = Name(consumerIdentity)
    # self.certificateName = self.keyChain.createIdentityAndCertificate(identityName)

    # self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

    print "Start NAC consumer test"
    face = Face()
    groupName = Name("/org/openmhealth/zhehao/data/fitness")
    consumerIdentity = Name("/org/openmhealth/zhehao/data/fitness")
    testConsumer = DPUConsumer(face, consumerIdentity, groupName, "policy_config/test_consumer.db")

    contentName = Name("/prefix/SAMPLE/a/b/c/20150825T080000")
    testConsumer.consume(contentName)
    print "Trying to consume: " + contentName.toUri()

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)

