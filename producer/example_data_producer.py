import unittest as ut
import os, time, json, random
from pyndn import Name, Data, Face, Interest
from pyndn.util import Blob, MemoryContentCache
from pyndn.encrypt import Producer, Schedule, Sqlite3ProducerDb, EncryptedContent
from pyndn.encrypt.algo import Encryptor, AesAlgorithm, RsaAlgorithm
from pyndn.encrypt.algo import EncryptParams, EncryptAlgorithmType
from pyndn.security import KeyChain, RsaKeyParams
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage, MemoryPrivateKeyStorage
from pyndn.security.policy import NoVerifyPolicyManager

from pyndn.encoding import ProtobufTlv

import repo_command_parameter_pb2
import repo_command_response_pb2

class SampleProducer(object):
    def __init__(self, face, username, memoryContentCache):
        # Set up face
        self.face = face

        # Set up the keyChain.
        identityStorage = MemoryIdentityStorage()
        privateKeyStorage = MemoryPrivateKeyStorage()
        self.keyChain = KeyChain(
          IdentityManager(identityStorage, privateKeyStorage),
          NoVerifyPolicyManager())

        identityName = Name(username)
        self.certificateName = self.keyChain.createIdentityAndCertificate(identityName)
        self.keyChain.getIdentityManager().setDefaultIdentity(identityName)

        self.face.setCommandSigningInfo(self.keyChain, self.certificateName)

        self.databaseFilePath = "policy_config/test_producer.db"
        self.catalogDatabaseFilePath = "policy_config/test_producer_catalog.db"
        try:
            os.remove(self.databaseFilePath)
        except OSError:
            # no such file
            pass
        try:
            os.remove(self.catalogDatabaseFilePath)
        except OSError:
            # no such file
            pass

        self.testDb = Sqlite3ProducerDb(self.databaseFilePath)
        self.catalogDb = Sqlite3ProducerDb(self.catalogDatabaseFilePath)

        # TODO: as of right now, catalog has a different suffix, so need another instance of producer; that producer cannot share
        # the same DB with the first producer, otherwise there won't be a self.onEncryptedKeys call; as the catalog producer uses 
        # its own C-key, and that key won't be encrypted by an E-key as no interest goes out
        # This sounds like something problematic from the library
        prefix = Name(username)
        suffix = Name("fitness/physical_activity/time_location")

        self.producer = Producer(Name(prefix), suffix, self.face, self.keyChain, self.testDb)

        catalogSuffix = Name(suffix).append("catalog")
        self.catalogProducer = Producer(Name(prefix), catalogSuffix, self.face, self.keyChain, self.catalogDb)

        self.memoryContentCache = memoryContentCache
        return

    def createContentKey(self, timeSlot):
        print "debug: createContentKey for data and catalog"
        contentKeyName = self.producer.createContentKey(timeSlot, self.onEncryptedKeys, self.onError)
        catalogKeyName = self.catalogProducer.createContentKey(timeSlot, self.onEncryptedKeys, self.onError)
        print contentKeyName.toUri()
        print catalogKeyName.toUri()

    def onError(self, code, msg):
        print str(code) + " : " + msg
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

    def onRepoData(self, interest, data):
        #print "received repo data: " + interest.getName().toUri()
        return

    def onRepoTimeout(self, interest):
        #print "repo command times out: " + interest.getName().getPrefix(-1).toUri()
        return

    def onEncryptedKeys(self, keys):
        print "debug: onEncryptedKeys called"
        if not keys:
            print "onEncryptedKeys: no keys in callback!"
        for i in range(0, len(keys)):
            print "onEncryptedKeys: produced encrypted key " + keys[i].getName().toUri()
            self.memoryContentCache.add(keys[i])
            self.initiateContentStoreInsertion("/ndn/edu/ucla/remap/ndnfit/repo", keys[i])
        return


def onDataNotFound(prefix, interest, face, interestFilterId, filter):
    print "Data not found for interest: " + interest.getName().toUri()
    return

def onRegisterFailed(prefix):
    print "Prefix registration failed"
    return

if __name__ == "__main__":
    print "Start NAC producer test"
    face = Face()
    memoryContentCache = MemoryContentCache(face)
    # Produce encrypted data for this user
    username = "/org/openmhealth/zhehao/"
    # Insert into this repo
    repoPrefix = "/ndn/edu/ucla/remap/ndnfit/repo"
    testProducer = SampleProducer(face, username, memoryContentCache)

    basetimeString = "20160620T080"
    baseZFill = 3
    baseLat = 34
    baseLng = -118
    # This should be less than 1 minute
    dataNum = 60

    # Create the content key once
    originalTimeString = basetimeString + str(0).zfill(baseZFill)
    timeFloat = Schedule.fromIsoString(originalTimeString)
    testProducer.createContentKey(timeFloat)

    memoryContentCache.registerPrefix(Name(username), onRegisterFailed, onDataNotFound)

    catalogData = Data(Name(username).append(Name("/data/fitness/physical_activity/time_location/catalog/")).append(originalTimeString).appendVersion(1))
    catalogContentArray = []

    for i in range(0, dataNum):
        emptyData = Data()
        timeString = basetimeString + str(i).zfill(baseZFill)
        timeFloat = Schedule.fromIsoString(timeString)

        dataObject = json.dumps({"lat": baseLat + random.randint(-10, 10), "timestamp": int(timeFloat / 1000), "lng": baseLng + random.randint(-10, 10)})
        testProducer.producer.produce(emptyData, timeFloat, Blob(dataObject, False))
        producedName = emptyData.getName()
        memoryContentCache.add(emptyData)
        print "Produced " + emptyData.getName().toUri()

        # Insert content into repo-ng
        testProducer.initiateContentStoreInsertion(repoPrefix, emptyData)
        catalogContentArray.append(int(timeFloat / 1000))

    catalogData.setContent(json.dumps(catalogContentArray))
    testProducer.keyChain.sign(catalogData)
    
    encryptedCatalogData = Data()
    testProducer.catalogProducer.produce(encryptedCatalogData, Schedule.fromIsoString(basetimeString + str(0).zfill(baseZFill)), Blob(json.dumps(catalogContentArray), False))
    print "Encrypted catalog name is " + encryptedCatalogData.getName().toUri()

    # Put the unencrypted as well as encrypted catalog into repo
    testProducer.initiateContentStoreInsertion(repoPrefix, catalogData)
    testProducer.initiateContentStoreInsertion(repoPrefix, encryptedCatalogData)

    memoryContentCache.add(catalogData)
    memoryContentCache.add(encryptedCatalogData)

    # Produce unencrypted data for this user
    unencryptedUserName = "/org/openmhealth/haitao"
    memoryContentCache.registerPrefix(Name(unencryptedUserName), onRegisterFailed, onDataNotFound)

    catalogData = Data(Name(unencryptedUserName).append(Name("/data/fitness/physical_activity/time_location/catalog/")).append(originalTimeString).appendVersion(1))
    catalogContentArray = []

    for i in range(0, dataNum):
        timeString = basetimeString + str(i).zfill(baseZFill)
        timeFloat = Schedule.fromIsoString(timeString)

        dataObject = json.dumps({"lat": baseLat + random.randint(-10, 10), "timestamp": int(timeFloat / 1000), "lng": baseLng + random.randint(-10, 10)})
        unencryptedData = Data(Name(unencryptedUserName).append(Name("/SAMPLE/fitness/physical_activity/time_location/")).append(timeString))
        unencryptedData.setContent(dataObject)
        testProducer.keyChain.sign(unencryptedData)

        # Insert content into repo-ng
        testProducer.initiateContentStoreInsertion("/ndn/edu/ucla/remap/ndnfit/repo", unencryptedData)
        catalogContentArray.append(int(timeFloat / 1000))

        memoryContentCache.add(unencryptedData)


    # Insert catalog into repo-ng
    catalogData.setContent(json.dumps(catalogContentArray))
    testProducer.keyChain.sign(catalogData)
    testProducer.initiateContentStoreInsertion(repoPrefix, catalogData)
    memoryContentCache.add(catalogData)

    while True:
        face.processEvents()
        # We need to sleep for a few milliseconds so we don't use 100% of the CPU.
        time.sleep(0.01)
