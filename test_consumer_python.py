import unittest as ut
import os, time, base64, json

from pyndn import Name, Data, Face, Interest
from pyndn.util import Blob, MemoryContentCache
from pyndn.encrypt import Schedule, Consumer, Sqlite3ConsumerDb, EncryptedContent

from pyndn.security import KeyType, KeyChain, RsaKeyParams
from pyndn.security.certificate import IdentityCertificate
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import BasicIdentityStorage, FilePrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

# Group manager first, consumer second, after group manager publishes E-Key (which should happen after addMember), 
# start producer, after producer creates C-key, run consumer again

class TestConsumer(object):
    def __init__(self, face):
        # Set up face
        self.face = face

        self.databaseFilePath = "policy_config/test_consumer.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass

        self.groupName = Name("/org/openmhealth/zhehao")

        # Set up the keyChain.
        identityStorage = BasicIdentityStorage()
        privateKeyStorage = FilePrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())
        # Authorized identity
        identityName = Name("/org/openmhealth/dvu-python-3")
        # Unauthorized identity
        #identityName = Name("/org/openmhealth/dvu-python-1")
        
        self.certificateName = self.keyChain.createIdentityAndCertificate(identityName)
        
        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        consumerKeyName = IdentityCertificate.certificateNameToPublicKeyName(self.certificateName)
        consumerCertificate = identityStorage.getCertificate(self.certificateName)
        self.consumer = Consumer(
          face, self.keyChain, self.groupName, identityName,
          Sqlite3ConsumerDb(self.databaseFilePath))

        # TODO: Read the private key to decrypt d-key...this may or may not be ideal
        base64Content = None
        with open(privateKeyStorage.nameTransform(consumerKeyName.toUri(), ".pri")) as keyFile:
            print privateKeyStorage.nameTransform(consumerKeyName.toUri(), ".pri")
            base64Content = keyFile.read()
            #print base64Content
        der = Blob(base64.b64decode(base64Content), False)
        self.consumer.addDecryptionKey(consumerKeyName, der)

        self.memoryContentCache = MemoryContentCache(self.face)
        self.memoryContentCache.registerPrefix(identityName, self.onRegisterFailed, self.onDataNotFound)
        self.memoryContentCache.add(consumerCertificate)

        accessRequestInterest = Interest(Name(self.groupName).append("read_access_request").append(self.certificateName).appendVersion(int(time.time())))
        self.face.expressInterest(accessRequestInterest, self.onAccessRequestData, self.onAccessRequestTimeout)
        print "Access request interest name: " + accessRequestInterest.getName().toUri()

        self.consumeCatalog = True
        return

    def onAccessRequestData(self, interest, data):
        print "Access request data: " + data.getName().toUri()
        print "Start consuming"
        self.startConsuming()
        return

    def onAccessRequestTimeout(self, interest):
        print "Access request times out: " + interest.getName().toUri()
        print "Assuming certificate sent and D-key generated, start consuming"
        self.startConsuming()
        return

    def startConsuming(self):
        if self.consumeCatalog:
            contentName = Name("/org/openmhealth/zhehao/SAMPLE/fitness/physical_activity/time_location/catalog/20160620T080000")
            self.consumer.consume(contentName, self.onCatalogConsumeComplete, self.onConsumeFailed)
            print "Trying to consume: " + contentName.toUri()
        else:
            contentName = Name("/org/openmhealth/zhehao/SAMPLE/fitness/physical_activity/time_location/")
            dataNum = 60
            baseZFill = 3
            basetimeString = "20160620T080"

            for i in range(0, dataNum):
                timeString = basetimeString + str(i).zfill(baseZFill)
                timeFloat = Schedule.fromIsoString(timeString)

                self.consumer.consume(Name(contentName).append(timeString), self.onConsumeComplete, self.onConsumeFailed)
                print "Trying to consume: " + Name(contentName).append(timeString).toUri()


    def onDataNotFound(self, prefix, interest, face, interestFilterId, filter):
        print "Data not found for interest: " + interest.getName().toUri()
        return

    def onRegisterFailed(self, prefix):
        print "Prefix registration failed: " + prefix.toUri()
        return

    def onCatalogConsumeComplete(self, data, result):
        print "Consume complete for catalog: " + data.getName().toUri()
        resultObject = json.loads(result.toRawStr())

        contentName = Name("/org/openmhealth/zhehao/SAMPLE/fitness/physical_activity/time_location/")
        
        for i in range(0, len(resultObject)):
            timeString = Schedule.toIsoString(int(resultObject[i]) * 1000)
            self.consumer.consume(Name(contentName).append(timeString), self.onConsumeComplete, self.onConsumeFailed)
            print "Trying to consume: " + Name(contentName).append(timeString).toUri()

    def onConsumeComplete(self, data, result):
        print "Consume complete for data name: " + data.getName().toUri()
        print result
        
        # Test the length of encrypted data

        # dataBlob = data.getContent()
        # dataContent = EncryptedContent()
        # dataContent.wireDecode(dataBlob)
        # encryptedData = dataContent.getPayload()
        # print len(encryptedData)

    # TODO: shouldn't this indicate the consumption of what has failed though
    def onConsumeFailed(self, code, message):
        print "Consume error " + str(code) + ": " + message

if __name__ == "__main__":
    print "Start NAC consumer test"
    face = Face()
    testConsumer = TestConsumer(face)

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)
